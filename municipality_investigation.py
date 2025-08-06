#!/usr/bin/env python3
"""
Municipality Deep Investigation - Brazilian Legislative Database
Deep text mining analysis to find hidden municipality data
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

# Database connection parameters
db_config = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def connect_to_database():
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(**db_config)
        print("Successfully connected to PostgreSQL database")
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def examine_table_structure(conn):
    """Examine database structure and identify relevant tables/columns"""
    cur = conn.cursor()
    
    # Get all tables
    cur.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    tables = [row[0] for row in cur.fetchall()]
    print(f"Available tables: {tables}")
    
    # Find main documents table - specifically look for 'documents'
    main_table = None
    if 'documents' in tables:
        main_table = 'documents'
    else:
        for table in tables:
            if any(keyword in table.lower() for keyword in ['documento', 'norma', 'lei']):
                main_table = table
                break
        
        if not main_table:
            main_table = tables[0] if tables else None
    
    if not main_table:
        print("No suitable table found")
        return None, []
    
    print(f"Using main table: {main_table}")
    
    # Get column information
    cur.execute(f"""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = '{main_table}'
        ORDER BY ordinal_position
    """)
    columns_info = cur.fetchall()
    columns = [col[0] for col in columns_info]
    
    print(f"Available columns: {columns}")
    
    # Get sample data
    cur.execute(f"SELECT * FROM {main_table} LIMIT 5")
    sample_data = cur.fetchall()
    print(f"Sample data (first 5 rows, first 3 columns):")
    for i, row in enumerate(sample_data[:5]):
        print(f"Row {i+1}: {row[:3]}...")
    
    # Get total record count
    cur.execute(f"SELECT COUNT(*) FROM {main_table}")
    total_records = cur.fetchone()[0]
    print(f"Total records: {total_records:,}")
    
    cur.close()
    return main_table, columns

def create_municipality_patterns():
    """Create comprehensive regex patterns for Brazilian municipality detection"""
    
    # Brazilian state abbreviations
    states = ['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
              'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
              'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO']
    
    # State full names
    state_names = ['Acre', 'Alagoas', 'Amapá', 'Amazonas', 'Bahia', 'Ceará',
                   'Distrito Federal', 'Espírito Santo', 'Goiás', 'Maranhão',
                   'Mato Grosso', 'Mato Grosso do Sul', 'Minas Gerais', 'Pará',
                   'Paraíba', 'Paraná', 'Pernambuco', 'Piauí', 'Rio de Janeiro',
                   'Rio Grande do Norte', 'Rio Grande do Sul', 'Rondônia', 'Roraima',
                   'Santa Catarina', 'São Paulo', 'Sergipe', 'Tocantins']
    
    patterns = {
        # Municipality - State (e.g., "São Paulo - SP", "Catanduva - SP")
        'municipality_state_hyphen': rf'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)\s*-\s*({"|".join(states)})',
        
        # Municipality (State) format
        'municipality_state_parentheses': rf'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)\s*\(\s*({"|".join(states)})\s*\)',
        
        # Municipality, State format
        'municipality_state_comma': rf'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+),\s*({"|".join(states)})',
        
        # "Município de X"
        'municipio_de': r'Munic[ií]pio\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)',
        
        # "Prefeitura de X" or "Prefeitura Municipal de X"
        'prefeitura_de': r'Prefeitura\s+(?:Municipal\s+)?de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)',
        
        # "Câmara Municipal de X"
        'camara_municipal': r'C[âa]mara\s+Municipal\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)',
        
        # State full names with municipalities
        'municipality_full_state': rf'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)\s*[-,]\s*({"|".join(state_names)})',
        
        # Common municipal authority patterns
        'tribunal_municipio': r'Tribunal\s+.*?(?:de|do|da)\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)',
        
        # CEP patterns that might indicate municipalities
        'cep_pattern': r'\b\d{5}-?\d{3}\b',
        
        # Generic municipality indicators
        'cidade_de': r'[Cc]idade\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)',
    }
    
    return patterns, states, state_names

def analyze_text_field(conn, table_name, field_name, patterns, sample_size=10000):
    """Analyze a specific text field for municipality patterns"""
    cur = conn.cursor()
    
    print(f"\n--- Analyzing field: {field_name} ---")
    
    # Get non-null count for this field
    cur.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {field_name} IS NOT NULL AND {field_name} != ''")
    non_null_count = cur.fetchone()[0]
    
    if non_null_count == 0:
        print(f"Field {field_name} has no non-null values")
        return {}
    
    print(f"Non-null values in {field_name}: {non_null_count:,}")
    
    # Sample data for analysis
    sample_limit = min(sample_size, non_null_count)
    cur.execute(f"""
        SELECT {field_name} 
        FROM {table_name} 
        WHERE {field_name} IS NOT NULL AND {field_name} != ''
        ORDER BY RANDOM()
        LIMIT {sample_limit}
    """)
    
    texts = [row[0] for row in cur.fetchall() if row[0]]
    print(f"Analyzing {len(texts)} text samples from {field_name}")
    
    # Analyze patterns
    field_results = {}
    
    for pattern_name, pattern in patterns.items():
        matches = []
        for text in texts:
            if text:
                found_matches = re.finditer(pattern, str(text), re.IGNORECASE)
                for match in found_matches:
                    if pattern_name in ['municipality_state_hyphen', 'municipality_state_parentheses', 
                                      'municipality_state_comma', 'municipality_full_state']:
                        # Extract municipality and state
                        municipality = match.group(1).strip()
                        state = match.group(2).strip()
                        matches.append((municipality, state, match.group(0)))
                    elif pattern_name in ['municipio_de', 'prefeitura_de', 'camara_municipal', 
                                        'tribunal_municipio', 'cidade_de']:
                        # Extract just municipality name
                        municipality = match.group(1).strip()
                        matches.append((municipality, None, match.group(0)))
                    else:
                        # Other patterns
                        matches.append((match.group(0), None, match.group(0)))
        
        if matches:
            field_results[pattern_name] = matches
            print(f"  {pattern_name}: {len(matches)} matches")
            # Show some examples
            for i, match in enumerate(matches[:5]):
                print(f"    Example {i+1}: {match[2]}")
    
    cur.close()
    return field_results

def main():
    """Main analysis function"""
    print("=" * 60)
    print("MUNICIPALITY DEEP INVESTIGATION")
    print("Brazilian Legislative Database Analysis")
    print("=" * 60)
    
    # Connect to database
    conn = connect_to_database()
    if not conn:
        return
    
    # Examine table structure
    table_name, columns = examine_table_structure(conn)
    if not table_name:
        conn.close()
        return
    
    # Create municipality detection patterns
    patterns, states, state_names = create_municipality_patterns()
    print(f"\nCreated {len(patterns)} municipality detection patterns")
    
    # Identify text fields to analyze
    text_fields = ['municipio', 'localidade', 'jurisdicao_original', 'autoridade', 
                  'titulo', 'ementa', 'resumo', 'conteudo', 'descricao', 
                  'origem', 'fonte', 'orgao']
    
    # Find existing text fields
    existing_text_fields = [field for field in text_fields if field in columns]
    
    # Add any other potential geographic fields
    geo_fields = [col for col in columns if any(keyword in col.lower() 
                                              for keyword in ['geo', 'local', 'munic', 'cidade', 'estado', 'uf', 'regiao'])]
    
    all_analysis_fields = list(set(existing_text_fields + geo_fields))
    
    print(f"\nFields to analyze: {all_analysis_fields}")
    
    # Analyze each field
    all_results = {}
    for field in all_analysis_fields:
        try:
            results = analyze_text_field(conn, table_name, field, patterns)
            all_results[field] = results
        except Exception as e:
            print(f"Error analyzing field {field}: {e}")
    
    # Compile comprehensive results
    print("\n" + "=" * 60)
    print("COMPREHENSIVE RESULTS SUMMARY")
    print("=" * 60)
    
    total_municipalities_found = 0
    unique_municipalities = set()
    pattern_counts = Counter()
    
    for field_name, field_results in all_results.items():
        if field_results:
            print(f"\nField: {field_name}")
            for pattern_name, matches in field_results.items():
                pattern_counts[pattern_name] += len(matches)
                print(f"  {pattern_name}: {len(matches)} matches")
                
                # Extract unique municipalities
                for match in matches:
                    if match[0]:  # municipality name
                        municipality_clean = re.sub(r'[^\w\s]', '', match[0]).strip()
                        if len(municipality_clean) > 2:  # Filter out very short matches
                            if match[1]:  # has state
                                unique_municipalities.add(f"{municipality_clean}, {match[1]}")
                            else:
                                unique_municipalities.add(municipality_clean)
    
    print(f"\n" + "=" * 40)
    print("FINAL STATISTICS")
    print("=" * 40)
    print(f"Total municipality references found: {sum(pattern_counts.values()):,}")
    print(f"Unique municipalities identified: {len(unique_municipalities):,}")
    
    print(f"\nPattern breakdown:")
    for pattern, count in pattern_counts.most_common():
        print(f"  {pattern}: {count:,}")
    
    print(f"\nSample unique municipalities found:")
    for i, municipality in enumerate(sorted(list(unique_municipalities))[:20]):
        print(f"  {i+1:2d}. {municipality}")
    
    if len(unique_municipalities) > 20:
        print(f"  ... and {len(unique_municipalities) - 20} more")
    
    # Save results to files
    results_df = pd.DataFrame([
        {'municipality': muni} for muni in unique_municipalities
    ])
    results_df.to_csv('found_municipalities.csv', index=False)
    print(f"\nResults saved to 'found_municipalities.csv'")
    
    # Close database connection
    conn.close()
    print("\nAnalysis completed successfully!")

if __name__ == "__main__":
    main()