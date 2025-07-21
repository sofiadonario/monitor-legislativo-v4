#!/usr/bin/env python3
"""
Analyze municipality names for potential spacing issues
"""

import psycopg2
import re
from difflib import SequenceMatcher

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Common Brazilian municipalities that might have spacing issues
KNOWN_MUNICIPALITIES = {
    # Format: "incorrect": "correct"
    "PonteNova": "Ponte Nova",
    "BeloHorizonte": "Belo Horizonte",
    "PortoAlegre": "Porto Alegre",
    "RiodeJaneiro": "Rio de Janeiro",
    "SaoPaulo": "São Paulo",
    "SãoPaulo": "São Paulo",
    "PortoVelho": "Porto Velho",
    "CampoGrande": "Campo Grande",
    "BoaVista": "Boa Vista",
    "RioBranco": "Rio Branco",
    "SantaMaria": "Santa Maria",
    "SantoAndre": "Santo André",
    "SantoAndré": "Santo André",
    "SaoBernardo": "São Bernardo",
    "SãoBernardo": "São Bernardo",
    "SaoCaetano": "São Caetano",
    "SãoCaetano": "São Caetano",
    "NovaIguacu": "Nova Iguaçu",
    "NovaIguaçu": "Nova Iguaçu",
    "VitoriadeConquista": "Vitória de Conquista",
    "VitóriadaConquista": "Vitória da Conquista",
    "JuizdeFora": "Juiz de Fora",
    "FeiradeSantana": "Feira de Santana",
    "RibeiraoPreto": "Ribeirão Preto",
    "RibeirãoPreto": "Ribeirão Preto",
    "SaoJose": "São José",
    "SãoJosé": "São José",
    "SaoLuis": "São Luís",
    "SãoLuís": "São Luís",
    "SaoGoncalo": "São Gonçalo",
    "SãoGonçalo": "São Gonçalo",
    "MaceiodoSul": "Maceió do Sul",
    "CaxiasdoSul": "Caxias do Sul",
    "PassoFundo": "Passo Fundo",
    "SantaCruz": "Santa Cruz",
    "VoltaRedonda": "Volta Redonda",
    "NovoHamburgo": "Novo Hamburgo",
    "SaoLeopoldo": "São Leopoldo",
    "SãoLeopoldo": "São Leopoldo",
    "VilaVelha": "Vila Velha",
    "SerraDourada": "Serra Dourada",
    "PedraAzul": "Pedra Azul",
    "AguasLindas": "Águas Lindas",
    "ÁguasLindas": "Águas Lindas",
}

def check_camel_case(text):
    """Check if text might be in CamelCase or missing spaces"""
    # Pattern to find lowercase followed by uppercase (potential missing space)
    pattern = r'[a-z][A-Z]'
    matches = list(re.finditer(pattern, text))
    return len(matches) > 0, matches

def suggest_spacing(text):
    """Suggest where spaces might be missing"""
    suggestions = []
    
    # Check for known municipalities
    for incorrect, correct in KNOWN_MUNICIPALITIES.items():
        if text.lower() == incorrect.lower():
            return correct
    
    # Check for camelCase pattern
    has_camel, matches = check_camel_case(text)
    if has_camel:
        # Build suggestion by inserting spaces
        result = text
        offset = 0
        for match in matches:
            pos = match.start() + 1 + offset
            result = result[:pos] + ' ' + result[pos:]
            offset += 1
        suggestions.append(result)
    
    # Check for common prefixes that should have spaces
    prefixes = ['Porto', 'Ponte', 'Santa', 'Santo', 'São', 'Sao', 'Nova', 'Novo', 
                'Belo', 'Boa', 'Vila', 'Campo', 'Alto', 'Bela', 'Rio', 'Pedra',
                'Aguas', 'Águas', 'Serra', 'Volta', 'Passo', 'Juiz', 'Feira']
    
    for prefix in prefixes:
        if text.startswith(prefix) and len(text) > len(prefix) and text[len(prefix)].isupper():
            suggestion = prefix + ' ' + text[len(prefix):]
            if suggestion not in suggestions:
                suggestions.append(suggestion)
    
    return suggestions[0] if suggestions else None

def analyze_municipalities():
    """Analyze municipality names in the database"""
    try:
        print("🔍 Analyzing municipality names for spacing issues...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Get all unique municipality values
        cursor.execute("""
            SELECT DISTINCT municipality, COUNT(*) as count
            FROM documents 
            WHERE municipality IS NOT NULL 
              AND municipality != ''
              AND municipality NOT LIKE '%ª Região%'
            GROUP BY municipality
            ORDER BY count DESC
        """)
        
        municipalities = cursor.fetchall()
        print(f"\n📊 Found {len(municipalities)} unique municipality values")
        
        # Analyze each municipality
        issues_found = []
        
        for mun, count in municipalities:
            # Check for potential issues
            has_camel, _ = check_camel_case(mun)
            suggestion = suggest_spacing(mun)
            
            if suggestion and suggestion != mun:
                issues_found.append({
                    'current': mun,
                    'suggested': suggestion,
                    'count': count
                })
        
        if issues_found:
            print(f"\n⚠️ Found {len(issues_found)} potential spacing issues:")
            for issue in issues_found:
                print(f"   '{issue['current']}' → '{issue['suggested']}' ({issue['count']} records)")
        
        # Check for specific patterns in the data
        print("\n🔍 Checking for specific patterns...")
        
        # Pattern 1: Words that should have "de" or "do" with spaces
        cursor.execute("""
            SELECT DISTINCT municipality, COUNT(*) as count
            FROM documents 
            WHERE municipality ~ '[a-z](de|do|da)[A-Z]'
               OR municipality ~ '[A-Z](de|do|da)[A-Z]'
            GROUP BY municipality
        """)
        
        de_do_issues = cursor.fetchall()
        if de_do_issues:
            print(f"\n   Found {len(de_do_issues)} municipalities with potential 'de/do/da' spacing issues:")
            for mun, count in de_do_issues[:5]:
                print(f"   '{mun}' ({count} records)")
        
        # Get sample records for verification
        if issues_found:
            print("\n📋 Sample records with potential issues:")
            for issue in issues_found[:3]:
                cursor.execute("""
                    SELECT id, estado, municipality, titulo
                    FROM documents 
                    WHERE municipality = %s
                    LIMIT 2
                """, (issue['current'],))
                samples = cursor.fetchall()
                
                print(f"\n   Municipality: '{issue['current']}' → '{issue['suggested']}'")
                for sample in samples:
                    print(f"      ID {sample[0]}: Estado='{sample[1]}', Title: {sample[3][:50]}...")
        
        # Also check if there are any other patterns in estado field
        print("\n🔍 Checking for similar issues in estado field...")
        cursor.execute("""
            SELECT DISTINCT estado, COUNT(*) as count
            FROM documents 
            WHERE estado ~ '[a-z][A-Z]'
               AND estado NOT LIKE '%-%'
               AND LENGTH(estado) > 2
            GROUP BY estado
            ORDER BY count DESC
        """)
        
        estado_issues = cursor.fetchall()
        if estado_issues:
            print(f"   Found {len(estado_issues)} potential issues in estado field:")
            for estado, count in estado_issues[:5]:
                print(f"   '{estado}' ({count} records)")
        
        conn.close()
        
        # Return the issues found for fixing
        return issues_found
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return []

if __name__ == "__main__":
    issues = analyze_municipalities()