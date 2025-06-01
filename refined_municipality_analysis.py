#!/usr/bin/env python3
"""
Refined Municipality Analysis - Brazilian Legislative Database
Focus on genuine municipality names, filtering out false positives
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

def get_known_brazilian_municipalities():
    """List of well-known Brazilian municipalities for validation"""
    return {
        'São Paulo', 'Rio de Janeiro', 'Brasília', 'Salvador', 'Fortaleza', 
        'Belo Horizonte', 'Manaus', 'Curitiba', 'Recife', 'Porto Alegre',
        'Goiânia', 'Belém', 'Guarulhos', 'Campinas', 'São Luís', 'Maceió',
        'Campo Grande', 'Teresina', 'São Gonçalo', 'Nova Iguaçu', 'Natal',
        'Contagem', 'São José dos Campos', 'Ribeirão Preto', 'Santos', 
        'Uberlândia', 'Sorocaba', 'Osasco', 'João Pessoa', 'Jaboatão dos Guararapes',
        'São José do Rio Preto', 'Campos dos Goytacazes', 'Londrina', 'Ananindeua',
        'Vila Velha', 'Caxias do Sul', 'Florianópolis', 'Macapá', 'Vitória',
        'Maringá', 'Aparecida de Goiânia', 'Joinville', 'Cuiabá', 'Blumenau',
        'Niterói', 'Juiz de Fora', 'Aracaju', 'Feira de Santana', 'Londrina',
        'Catanduva', 'Bauru', 'Araraquara', 'Piracicaba', 'Franca', 'Taubaté',
        'Limeira', 'Suzano', 'Presidente Prudente', 'São Carlos', 'Marília',
        'Americana', 'Jundiaí', 'Indaiatuba', 'Itu', 'Botucatu', 'Araras',
        'Rio Claro', 'Assis', 'Barretos', 'Ourinhos', 'Bragança Paulista',
        'Itapetininga', 'Mogi das Cruzes', 'São José dos Campos', 'Guaratinguetá',
        'Caraguatatuba', 'Itanhaém', 'Santos', 'São Vicente', 'Cubatão',
        'Praia Grande', 'Diadema', 'Santo André', 'São Bernardo do Campo',
        'São Caetano do Sul', 'Mauá', 'Ribeirão Pires', 'Rio Grande da Serra'
    }

def create_refined_patterns():
    """Create refined patterns focused on genuine municipality detection"""
    
    # Brazilian state abbreviations
    states = ['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
              'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
              'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO']
    
    patterns = {
        # Very specific municipality patterns with state
        'municipality_state_parentheses': rf'(?:Município|município|Prefeitura|prefeitura)?\s*(?:de|do|da)?\s*([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)\s*\(\s*({"|".join(states)})\s*\)',
        
        # Municipality with hyphen and state (more restrictive)
        'municipality_state_hyphen_specific': rf'(?:Município|município|Prefeitura|prefeitura)?\s*(?:de|do|da)?\s*([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)\s*-\s*({"|".join(states)})\b',
        
        # Official municipality patterns
        'municipio_de_clean': r'Munic[ií]pio\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)(?:\s|,|\.|\(|$)',
        
        # Prefeitura patterns
        'prefeitura_municipal': r'Prefeitura\s+Municipal\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)(?:\s|,|\.|\(|$)',
        
        # Câmara Municipal patterns
        'camara_municipal_clean': r'C[âa]mara\s+Municipal\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)(?:\s|,|\.|\(|$)',
        
        # Tribunal patterns with location
        'tribunal_comarca': r'(?:Comarca|comarca)\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)(?:\s|,|\.|\(|$)',
        
        # Capital city patterns
        'capital_patterns': r'(?:Capital|capital)\s+(?:de|do|da)\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)(?:\s|,|\.|\(|$)',
        
        # City authorization patterns common in laws
        'autoriza_municipio': r'Autoriza\s+o\s+Munic[ií]pio\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]{3,30}?)(?:\s|,|\.|\(|$)',
    }
    
    return patterns, states

def is_valid_municipality_name(name):
    """Validate if a string looks like a real municipality name"""
    if not name or len(name.strip()) < 3:
        return False
    
    name = name.strip()
    
    # Remove if it's clearly not a municipality name
    invalid_patterns = [
        # Legal/technical terms
        r'^(SE|PR|MA|ES|BA|CE|PA|AM|AC|AL|AP|DF|GO|MT|MS|MG|PB|PE|PI|RJ|RN|RS|RO|RR|SC|SP|TO)$',
        r'^(Art|art|Lei|lei|Dec|dec|Decreto|decreto)\.?\s*\d+',
        r'^\d+[\-\.]?\d*$',  # Just numbers
        r'^[A-Z]{2,}$',      # All caps abbreviations
        r'[0-9]{5,}',        # Contains long numbers
        r'^(E|OU|DE|DO|DA|EM|COM|PARA|POR|CONTRA|SOBRE|ENTRE)$',  # Prepositions
        # Common legal phrases
        r'ADMITE[\-\s]SE',
        r'TRATANDO[\-\s]SE',
        r'ESTABELECER[\-\s]SE',
        r'TRANSMITE[\-\s]SE',
        # Very long phrases (probably not municipality names)
        r'.{50,}',
    ]
    
    for pattern in invalid_patterns:
        if re.search(pattern, name, re.IGNORECASE):
            return False
    
    # Must contain at least one letter
    if not re.search(r'[a-zA-ZáàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]', name):
        return False
    
    # Should look like a proper name (title case or sentence case)
    if name.isupper() and len(name) > 10:  # Very long all-caps strings are suspicious
        return False
    
    return True

def analyze_field_refined(conn, table_name, field_name, patterns, known_municipalities, sample_size=20000):
    """Refined analysis of a specific field for municipality patterns"""
    cur = conn.cursor()
    
    print(f"\n--- REFINED ANALYSIS: {field_name} ---")
    
    # Get non-null count
    cur.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {field_name} IS NOT NULL AND {field_name} != ''")
    non_null_count = cur.fetchone()[0]
    
    if non_null_count == 0:
        print(f"Field {field_name} has no data")
        return {}
    
    print(f"Non-null values: {non_null_count:,}")
    
    # Sample data
    sample_limit = min(sample_size, non_null_count)
    cur.execute(f"""
        SELECT {field_name} 
        FROM {table_name} 
        WHERE {field_name} IS NOT NULL AND {field_name} != ''
        ORDER BY RANDOM()
        LIMIT {sample_limit}
    """)
    
    texts = [row[0] for row in cur.fetchall() if row[0]]
    print(f"Analyzing {len(texts)} samples")
    
    # Track results
    valid_municipalities = set()
    pattern_results = {}
    
    for pattern_name, pattern in patterns.items():
        matches = []
        for text in texts:
            if text:
                found_matches = re.finditer(pattern, str(text), re.IGNORECASE)
                for match in found_matches:
                    if pattern_name in ['municipality_state_parentheses', 'municipality_state_hyphen_specific']:
                        municipality = match.group(1).strip()
                        state = match.group(2).strip()
                        full_match = match.group(0)
                        
                        if is_valid_municipality_name(municipality):
                            matches.append((municipality, state, full_match))
                            valid_municipalities.add(f"{municipality}, {state}")
                    else:
                        municipality = match.group(1).strip()
                        full_match = match.group(0)
                        
                        if is_valid_municipality_name(municipality):
                            matches.append((municipality, None, full_match))
                            valid_municipalities.add(municipality)
        
        if matches:
            pattern_results[pattern_name] = matches
            print(f"  {pattern_name}: {len(matches)} valid matches")
            # Show examples
            for i, (muni, state, full) in enumerate(matches[:5]):
                if state:
                    print(f"    {i+1}. {muni}, {state} (from: {full[:50]}...)")
                else:
                    print(f"    {i+1}. {muni} (from: {full[:50]}...)")
    
    # Check for known municipalities
    known_found = valid_municipalities.intersection(known_municipalities)
    if known_found:
        print(f"  ✓ Found {len(known_found)} known municipalities!")
        for known in sorted(list(known_found))[:5]:
            print(f"    - {known}")
    
    cur.close()
    return pattern_results, valid_municipalities

def main():
    """Main refined analysis function"""
    print("=" * 70)
    print("REFINED MUNICIPALITY DEEP INVESTIGATION")
    print("Filtering for genuine Brazilian municipality names")
    print("=" * 70)
    
    # Connect to database
    conn = psycopg2.connect(**db_config)
    print("Connected to database")
    
    # Get known municipalities for validation
    known_municipalities = get_known_brazilian_municipalities()
    print(f"Using {len(known_municipalities)} known municipalities for validation")
    
    # Create refined patterns
    patterns, states = create_refined_patterns()
    print(f"Created {len(patterns)} refined detection patterns")
    
    # Analyze specific fields most likely to contain real municipality data
    priority_fields = ['titulo', 'ementa', 'municipio']
    
    all_valid_municipalities = set()
    all_pattern_counts = Counter()
    field_results = {}
    
    for field in priority_fields:
        try:
            results, valid_munis = analyze_field_refined(conn, 'documents', field, patterns, known_municipalities)
            field_results[field] = results
            all_valid_municipalities.update(valid_munis)
            
            # Count patterns
            for pattern_name, matches in results.items():
                all_pattern_counts[pattern_name] += len(matches)
                
        except Exception as e:
            print(f"Error analyzing field {field}: {e}")
    
    # Comprehensive results
    print("\n" + "=" * 50)
    print("REFINED RESULTS SUMMARY")
    print("=" * 50)
    
    print(f"Total valid municipality references: {sum(all_pattern_counts.values()):,}")
    print(f"Unique valid municipalities: {len(all_valid_municipalities):,}")
    
    print(f"\nPattern effectiveness:")
    for pattern, count in all_pattern_counts.most_common():
        print(f"  {pattern}: {count:,}")
    
    # Show sample municipalities found
    print(f"\nSample valid municipalities discovered:")
    for i, municipality in enumerate(sorted(list(all_valid_municipalities))[:30]):
        print(f"  {i+1:2d}. {municipality}")
    
    if len(all_valid_municipalities) > 30:
        print(f"  ... and {len(all_valid_municipalities) - 30} more")
    
    # Check against known municipalities
    known_found = all_valid_municipalities.intersection(known_municipalities)
    print(f"\nKnown major municipalities found: {len(known_found)}")
    for known in sorted(list(known_found)):
        print(f"  ✓ {known}")
    
    # Estimate total municipality coverage
    print(f"\nESTIMATED TOTAL COVERAGE:")
    print(f"- Documents with municipality field populated: 2,994")
    print(f"- Additional municipalities found in text: ~{len(all_valid_municipalities):,}")
    print(f"- Potential total municipality coverage: ~{2994 + len(all_valid_municipalities):,} documents")
    
    # Save refined results
    refined_df = pd.DataFrame([
        {'municipality': muni, 'source': 'text_mining'} for muni in all_valid_municipalities
    ])
    refined_df.to_csv('refined_municipalities_found.csv', index=False)
    print(f"\nRefined results saved to 'refined_municipalities_found.csv'")
    
    # Additional field analysis for completeness
    print(f"\n" + "=" * 50)
    print("ADDITIONAL FIELD ANALYSIS")
    print("=" * 50)
    
    # Check what's actually in the municipio field
    cur = conn.cursor()
    cur.execute("SELECT municipio, COUNT(*) as count FROM documents WHERE municipio IS NOT NULL GROUP BY municipio ORDER BY count DESC LIMIT 20")
    municipio_data = cur.fetchall()
    
    print("Top municipalities in 'municipio' field:")
    for muni, count in municipio_data:
        print(f"  {muni}: {count:,} documents")
    
    # Check autoridade field for municipal authorities
    cur.execute("SELECT autoridade, COUNT(*) as count FROM documents WHERE autoridade IS NOT NULL AND (LOWER(autoridade) LIKE '%prefeitura%' OR LOWER(autoridade) LIKE '%câmara%' OR LOWER(autoridade) LIKE '%municipal%') GROUP BY autoridade ORDER BY count DESC LIMIT 10")
    autoridade_data = cur.fetchall()
    
    if autoridade_data:
        print("\nMunicipal authorities found:")
        for auth, count in autoridade_data:
            print(f"  {auth}: {count:,} documents")
    
    conn.close()
    print("\nRefined analysis completed!")

if __name__ == "__main__":
    main()