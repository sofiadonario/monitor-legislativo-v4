#!/usr/bin/env python3
"""
LexML Enhanced Research Engine Demo
==================================

Demonstrates the vocabulary expansion and research capabilities
of the integrated LexML system for academic transport legislation research.

Run this script to see how search terms are expanded and enhanced
for comprehensive academic research.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def demonstrate_vocabulary_expansion():
    """Demonstrate vocabulary expansion capabilities."""
    print("🔬 LexML Enhanced Research Engine - Vocabulary Expansion Demo")
    print("=" * 70)
    
    # Sample transport-related search terms
    demo_terms = [
        "transporte de carga",
        "sustentabilidade",
        "ANTT",
        "combustível",
        "logística"
    ]
    
    # Load transport terms from file
    transport_terms_file = project_root / 'transport_terms.txt'
    if transport_terms_file.exists():
        with open(transport_terms_file, 'r', encoding='utf-8') as f:
            all_transport_terms = [line.strip() for line in f if line.strip()]
        
        print(f"📚 Loaded {len(all_transport_terms)} specialized transport terms")
        print()
        
        # Demonstrate expansion for each demo term
        for term in demo_terms:
            print(f"🔍 Original term: '{term}'")
            
            # Find related terms (simple keyword matching for demo)
            related_terms = []
            term_lower = term.lower()
            
            # Basic expansion logic (simplified version of actual SKOS expansion)
            for transport_term in all_transport_terms:
                if (term_lower in transport_term.lower() or 
                    any(word in transport_term.lower() for word in term_lower.split())):
                    related_terms.append(transport_term)
            
            # Add domain-specific expansions
            expansion_map = {
                'transporte': ['mobilidade', 'modal', 'logística', 'frete'],
                'carga': ['mercadoria', 'commodity', 'produtos'],
                'sustentabilidade': ['verde', 'limpo', 'renovável', 'descarbonização'],
                'antt': ['regulamentação', 'habilitação', 'RNTRC'],
                'combustível': ['energia', 'diesel', 'biodiesel', 'etanol']
            }
            
            for key, expansions in expansion_map.items():
                if key in term_lower:
                    related_terms.extend(expansions)
            
            # Remove duplicates and limit
            expanded_terms = list(set(related_terms))[:8]
            
            print(f"📈 Expanded to {len(expanded_terms)} terms:")
            for i, expanded_term in enumerate(expanded_terms, 1):
                print(f"   {i}. {expanded_term}")
            
            print()
    
    else:
        print("❌ Transport terms file not found. Basic demo only.")

def demonstrate_research_features():
    """Demonstrate research and academic features."""
    print("🎓 Academic Research Features")
    print("=" * 40)
    
    features = [
        ("SKOS Vocabularies", "W3C-compliant controlled vocabularies for transport legislation"),
        ("Term Expansion", "Automatic expansion of search terms using domain knowledge"),
        ("Multi-Source Search", "Aggregate results from LexML + 11 regulatory agencies"),
        ("Academic Citations", "Automatic generation of Harvard-style citations"),
        ("FRBROO Metadata", "Academic metadata standards for research integrity"),
        ("Transport Specialization", "Domain-specific vocabulary for Brazilian transport regulation"),
        ("Real-Time Access", "Live connection to thousands of legislative documents"),
        ("Vocabulary Analytics", "Track which expanded terms are most effective")
    ]
    
    for feature, description in features:
        print(f"✅ {feature}: {description}")
    
    print()

def demonstrate_api_endpoints():
    """Show the new API endpoints for vocabulary research."""
    print("🌐 New Research API Endpoints")
    print("=" * 35)
    
    endpoints = [
        ("GET /api/v1/search", "Enhanced search with LexML priority and vocabulary expansion"),
        ("GET /api/v1/vocabulary/status", "Check status of vocabulary system and research engine"),
        ("GET /api/v1/vocabulary/expand/{term}", "Preview vocabulary expansion for any term"),
        ("GET /api/v1/sources", "List all available data sources including LexML"),
        ("POST /api/v1/export/csv", "Export research results with academic metadata"),
        ("POST /api/v1/export/xlsx", "Export to Excel with enhanced research data")
    ]
    
    for endpoint, description in endpoints:
        print(f"🔗 {endpoint}")
        print(f"   {description}")
        print()

def main():
    """Run the complete LexML demonstration."""
    print()
    demonstrate_vocabulary_expansion()
    demonstrate_research_features()
    demonstrate_api_endpoints()
    
    print("🚀 LexML Enhanced Research Engine Integration Complete!")
    print()
    print("The platform has been transformed from showing 5 embedded documents")
    print("to providing access to thousands of real legislative documents with")
    print("sophisticated vocabulary-aware search capabilities.")
    print()
    print("Next steps:")
    print("1. Deploy to Railway/GitHub Pages")
    print("2. Test vocabulary expansion in browser")
    print("3. Verify multi-source search aggregation")
    print("4. Validate academic citation generation")

if __name__ == "__main__":
    main()