#!/usr/bin/env python3
"""
Deep search for camelCase patterns across all text fields
"""

import psycopg2
import re
from collections import defaultdict

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Common Brazilian municipality name patterns that might appear in camelCase
KNOWN_MUNICIPALITY_PATTERNS = [
    # Common prefixes in Brazilian city names
    "Porto", "Ponte", "Santa", "Santo", "São", "Sao", "Nova", "Novo",
    "Belo", "Boa", "Vila", "Campo", "Alto", "Alta", "Bela", "Rio",
    "Pedra", "Agua", "Águas", "Serra", "Volta", "Passo", "Juiz",
    "Feira", "Monte", "Montes", "Ouro", "Prata", "Cruz", "Barra",
    "Costa", "Praia", "Vale", "Velho", "Velha", "Grande", "Pequeno",
    "Norte", "Sul", "Leste", "Oeste", "Centro", "Jardim", "Parque"
]

def is_likely_municipality(word):
    """Check if a camelCase word is likely a municipality name"""
    # Check if it starts with a known prefix
    for prefix in KNOWN_MUNICIPALITY_PATTERNS:
        if word.startswith(prefix) and len(word) > len(prefix):
            return True
    
    # Check if it contains "do", "da", "de" patterns
    if re.search(r'[a-z](do|da|de|Do|Da|De)[A-Z]', word):
        return True
    
    return False

def extract_camelcase_municipalities(text):
    """Extract potential municipality names in camelCase"""
    if not text:
        return []
    
    municipalities = []
    
    # Find all camelCase patterns
    # Pattern 1: lowercase followed by uppercase
    pattern1 = re.finditer(r'\b([A-Z]?[a-z]+[A-Z][a-zA-Z]*)\b', text)
    # Pattern 2: Multiple capital letters in a word
    pattern2 = re.finditer(r'\b([A-Z][a-z]+[A-Z][a-zA-Z]*)\b', text)
    
    for match in pattern1:
        word = match.group(1)
        if is_likely_municipality(word):
            municipalities.append(word)
    
    for match in pattern2:
        word = match.group(1)
        if is_likely_municipality(word):
            municipalities.append(word)
    
    return list(set(municipalities))

def fix_municipality_name(name):
    """Fix a municipality name with proper spacing"""
    # Add spaces before capital letters that follow lowercase
    fixed = re.sub(r'([a-z])([A-Z])', r'\1 \2', name)
    
    # Handle patterns like "OuroPreto"
    fixed = re.sub(r'([A-Z][a-z]+)([A-Z])', r'\1 \2', fixed)
    
    # Fix Portuguese prepositions
    fixed = re.sub(r'\s+(De|de)\s+', ' de ', fixed)
    fixed = re.sub(r'\s+(Do|do)\s+', ' do ', fixed)
    fixed = re.sub(r'\s+(Da|da)\s+', ' da ', fixed)
    fixed = re.sub(r'\s+(Dos|dos)\s+', ' dos ', fixed)
    fixed = re.sub(r'\s+(Das|das)\s+', ' das ', fixed)
    
    # Special cases for "e" (and)
    fixed = re.sub(r'\s+(E|e)\s+', ' e ', fixed)
    
    return fixed

def deep_search():
    """Perform deep search across all fields"""
    try:
        print("🔍 Deep searching for camelCase municipality patterns...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        all_patterns = defaultdict(int)
        field_occurrences = defaultdict(lambda: defaultdict(int))
        
        # 1. Search in all text fields
        print("\n1️⃣ Searching across all text fields...")
        
        fields_to_check = [
            ('titulo', 'title'),
            ('conteudo', 'content'),
            ('municipality', 'municipality'),
            ('document_description', 'description'),
            ('document_summary', 'summary'),
            ('search_term', 'search_term')
        ]
        
        for field, field_name in fields_to_check:
            print(f"\n   Checking {field_name} field...")
            
            # Get sample of records with potential camelCase
            query = f"""
                SELECT id, {field}
                FROM documents 
                WHERE {field} ~ '[a-z][A-Z]'
                   OR {field} ~ '[A-Z][a-z]+[A-Z]'
                LIMIT 500
            """
            
            cursor.execute(query)
            records = cursor.fetchall()
            
            field_patterns = defaultdict(int)
            for id, text in records:
                if text:
                    municipalities = extract_camelcase_municipalities(text)
                    for mun in municipalities:
                        field_patterns[mun] += 1
                        all_patterns[mun] += 1
                        field_occurrences[mun][field_name] += 1
            
            if field_patterns:
                print(f"   Found {len(field_patterns)} unique patterns")
                # Show top 5
                sorted_patterns = sorted(field_patterns.items(), key=lambda x: x[1], reverse=True)
                for pattern, count in sorted_patterns[:5]:
                    fixed = fix_municipality_name(pattern)
                    if fixed != pattern:
                        print(f"      '{pattern}' → '{fixed}' ({count} occurrences)")
        
        # 2. Search in metadata JSON
        print("\n2️⃣ Searching in metadata JSON fields...")
        cursor.execute("""
            SELECT id, 
                   metadata->>'original_state' as orig_state,
                   metadata->>'original_municipality' as orig_mun,
                   metadata->>'document_description' as desc
            FROM documents 
            WHERE metadata IS NOT NULL
            LIMIT 500
        """)
        
        metadata_records = cursor.fetchall()
        metadata_patterns = defaultdict(int)
        
        for id, orig_state, orig_mun, desc in metadata_records:
            for text in [orig_state, orig_mun, desc]:
                if text:
                    municipalities = extract_camelcase_municipalities(text)
                    for mun in municipalities:
                        metadata_patterns[mun] += 1
                        all_patterns[mun] += 1
                        field_occurrences[mun]['metadata'] += 1
        
        if metadata_patterns:
            print(f"   Found {len(metadata_patterns)} patterns in metadata")
        
        # 3. Show comprehensive results
        print("\n📊 COMPREHENSIVE RESULTS:")
        print(f"\nTotal unique camelCase municipality patterns found: {len(all_patterns)}")
        
        if all_patterns:
            print("\n🏘️ Top 20 camelCase municipality patterns:")
            sorted_all = sorted(all_patterns.items(), key=lambda x: x[1], reverse=True)
            
            for i, (pattern, total_count) in enumerate(sorted_all[:20], 1):
                fixed = fix_municipality_name(pattern)
                if fixed != pattern:
                    print(f"\n{i}. '{pattern}' → '{fixed}' (Total: {total_count} occurrences)")
                    # Show where it appears
                    fields = field_occurrences[pattern]
                    field_list = [f"{field}: {count}" for field, count in fields.items()]
                    print(f"   Found in: {', '.join(field_list)}")
        
        # 4. Generate SQL update statements
        print("\n💾 Generating fix recommendations...")
        
        fixes_needed = []
        for pattern in all_patterns:
            fixed = fix_municipality_name(pattern)
            if fixed != pattern:
                fixes_needed.append((pattern, fixed))
        
        print(f"\nTotal fixes needed: {len(fixes_needed)}")
        
        if fixes_needed:
            print("\n📝 SQL update patterns to apply:")
            for i, (original, fixed) in enumerate(fixes_needed[:10], 1):
                print(f"{i}. Replace '{original}' with '{fixed}'")
        
        conn.close()
        return fixes_needed
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return []

if __name__ == "__main__":
    fixes = deep_search()