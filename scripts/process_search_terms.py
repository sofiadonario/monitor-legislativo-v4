#!/usr/bin/env python3
"""
Process search terms and clean them for effective LexML searching
"""

import re
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_enhanced_strategy import load_search_terms

def clean_search_terms(terms_file: str) -> list:
    """
    Clean and process search terms for optimal LexML searching
    """
    raw_terms = load_search_terms(terms_file)
    
    cleaned_terms = []
    
    for term in raw_terms:
        # Skip metadata and instructions
        if any(skip in term.lower() for skip in [
            'brasil:', 'itens', 'úteis:', 'notas de uso', 'importante:',
            'exemplo de busca', 'fontes recomendadas', 'combinações booleanas',
            'sites do', 'portais', 'diário oficial', 'câmara e senado'
        ]):
            continue
            
        # Clean the term
        term = term.strip()
        
        # Remove quotation marks for simple terms
        if term.startswith('"') and term.endswith('"'):
            term = term[1:-1]
        
        # Skip empty or very short terms
        if len(term) < 3:
            continue
            
        # Skip terms with complex boolean operators for now
        if ' AND ' in term or ' OR ' in term or '(' in term:
            continue
            
        # Skip URLs and file extensions
        if 'http' in term or '.gov' in term or '.com' in term:
            continue
            
        # Skip numbers-only terms
        if term.isdigit():
            continue
            
        # Clean up the term
        term = re.sub(r'[^\w\s\-]', '', term)  # Keep only letters, numbers, spaces, hyphens
        term = ' '.join(term.split())  # Normalize whitespace
        
        if term and len(term) >= 3:
            cleaned_terms.append(term)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_terms = []
    for term in cleaned_terms:
        term_lower = term.lower()
        if term_lower not in seen:
            seen.add(term_lower)
            unique_terms.append(term)
    
    return unique_terms

def categorize_terms(terms: list) -> dict:
    """
    Categorize terms by type for better processing
    """
    categories = {
        'transport_general': [],
        'fuel_energy': [],
        'technology': [],
        'regulation': [],
        'infrastructure': [],
        'economics': [],
        'environment': [],
        'equipment': [],
        'operations': []
    }
    
    # Keywords for categorization
    fuel_keywords = ['combustível', 'energia', 'gás', 'diesel', 'biodiesel', 'etanol', 'hidrogênio', 'biometano']
    tech_keywords = ['tecnologia', 'autônomo', 'telemetria', 'rastreamento', 'assistiva', 'conversão']
    reg_keywords = ['contran', 'antt', 'registro', 'licenciamento', 'habilitação', 'rntrc', 'segurança']
    infra_keywords = ['posto', 'infraestrutura', 'terminal', 'centro', 'armazém']
    econ_keywords = ['ipi', 'icms', 'incentivo', 'isenção', 'benefício', 'financiamento', 'tributário']
    env_keywords = ['eficiência', 'emissões', 'descarbonização', 'gases', 'rotulagem', 'consumo']
    equip_keywords = ['máquina', 'implemento', 'reboque', 'carreta', 'bitrem', 'equipamento']
    ops_keywords = ['transportador', 'empresa', 'operador', 'embarcador', 'terceirização', 'contrato', 'frete']
    
    for term in terms:
        term_lower = term.lower()
        
        # Check categories
        if any(keyword in term_lower for keyword in fuel_keywords):
            categories['fuel_energy'].append(term)
        elif any(keyword in term_lower for keyword in tech_keywords):
            categories['technology'].append(term)
        elif any(keyword in term_lower for keyword in reg_keywords):
            categories['regulation'].append(term)
        elif any(keyword in term_lower for keyword in infra_keywords):
            categories['infrastructure'].append(term)
        elif any(keyword in term_lower for keyword in econ_keywords):
            categories['economics'].append(term)
        elif any(keyword in term_lower for keyword in env_keywords):
            categories['environment'].append(term)
        elif any(keyword in term_lower for keyword in equip_keywords):
            categories['equipment'].append(term)
        elif any(keyword in term_lower for keyword in ops_keywords):
            categories['operations'].append(term)
        else:
            categories['transport_general'].append(term)
    
    return categories

def main():
    """Process and categorize search terms"""
    print("=== Processing Search Terms ===")
    
    terms_file = 'termos_busca.txt'
    
    # Clean terms
    cleaned_terms = clean_search_terms(terms_file)
    print(f"Cleaned terms: {len(cleaned_terms)}")
    
    # Categorize terms
    categories = categorize_terms(cleaned_terms)
    
    print("\n--- Terms by Category ---")
    total_categorized = 0
    for category, terms in categories.items():
        if terms:
            print(f"{category}: {len(terms)} terms")
            total_categorized += len(terms)
            # Show first few terms as examples
            examples = terms[:3]
            print(f"  Examples: {', '.join(examples)}")
    
    print(f"\nTotal categorized: {total_categorized}")
    
    # Save cleaned terms to file
    output_file = 'cleaned_search_terms.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        for term in cleaned_terms:
            f.write(f"{term}\n")
    
    print(f"✓ Cleaned terms saved to: {output_file}")
    
    # Save categorized terms
    categories_file = 'categorized_terms.txt'
    with open(categories_file, 'w', encoding='utf-8') as f:
        for category, terms in categories.items():
            if terms:
                f.write(f"\n=== {category.upper()} ===\n")
                for term in terms:
                    f.write(f"{term}\n")
    
    print(f"✓ Categorized terms saved to: {categories_file}")
    
    return cleaned_terms

if __name__ == "__main__":
    main()