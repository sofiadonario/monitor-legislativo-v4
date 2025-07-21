#!/usr/bin/env python3
"""
Find all camelCase patterns in the database that likely need spacing
"""

import psycopg2
import re
from collections import defaultdict

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def find_camelcase_pattern(text):
    """Find all camelCase patterns in text"""
    if not text:
        return []
    
    # Pattern: lowercase letter followed by uppercase letter
    # or uppercase letter followed by lowercase then uppercase (like OuroPreto)
    patterns = []
    
    # Find all words that might have camelCase
    words = re.findall(r'\b[A-Za-z]+\b', text)
    for word in words:
        # Check for lowercase followed by uppercase
        if re.search(r'[a-z][A-Z]', word):
            patterns.append(word)
        # Check for patterns like "OuroPreto" (capital letter, lowercase letters, then another capital)
        elif re.search(r'^[A-Z][a-z]+[A-Z]', word):
            patterns.append(word)
    
    return patterns

def suggest_fix(word):
    """Suggest how to fix a camelCase word"""
    # First check if it's a known acronym or should stay together
    keep_together = ['PhD', 'URL', 'API', 'PDF', 'HTML', 'XML', 'JSON', 'CSV']
    if word in keep_together:
        return None
    
    # For patterns like "OuroPreto" or "PortoAlegre"
    # Insert space before capital letters that follow lowercase letters
    fixed = re.sub(r'([a-z])([A-Z])', r'\1 \2', word)
    
    # For patterns starting with capital like "OuroPreto"
    # This handles cases where first word is capitalized
    fixed = re.sub(r'([A-Z][a-z]+)([A-Z])', r'\1 \2', fixed)
    
    # Handle special cases with Portuguese prepositions
    # Replace "De" with "de", "Do" with "do", "Da" with "da"
    fixed = re.sub(r'\s+De\s+', ' de ', fixed)
    fixed = re.sub(r'\s+Do\s+', ' do ', fixed)
    fixed = re.sub(r'\s+Da\s+', ' da ', fixed)
    fixed = re.sub(r'\s+Dos\s+', ' dos ', fixed)
    fixed = re.sub(r'\s+Das\s+', ' das ', fixed)
    
    return fixed if fixed != word else None

def analyze_database():
    """Analyze database for camelCase patterns"""
    try:
        print("🔍 Searching for camelCase patterns in Railway PostgreSQL...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Dictionary to store findings
        findings = defaultdict(list)
        
        # 1. Check municipality field
        print("\n1️⃣ Checking municipality field...")
        cursor.execute("""
            SELECT DISTINCT municipality, COUNT(*) as count
            FROM documents 
            WHERE municipality IS NOT NULL 
              AND municipality != ''
              AND municipality !~ '^\\d+ª Região'
            GROUP BY municipality
            ORDER BY municipality
        """)
        
        municipalities = cursor.fetchall()
        for mun, count in municipalities:
            camelcase_words = find_camelcase_pattern(mun)
            for word in camelcase_words:
                fix = suggest_fix(word)
                if fix:
                    findings['municipality'].append({
                        'original': mun,
                        'word': word,
                        'suggested_fix': fix,
                        'count': count
                    })
        
        # 2. Check estado field
        print("2️⃣ Checking estado field...")
        cursor.execute("""
            SELECT DISTINCT estado, COUNT(*) as count
            FROM documents 
            WHERE estado IS NOT NULL 
              AND estado != ''
              AND LENGTH(estado) > 2
            GROUP BY estado
            ORDER BY estado
        """)
        
        estados = cursor.fetchall()
        for estado, count in estados:
            camelcase_words = find_camelcase_pattern(estado)
            for word in camelcase_words:
                fix = suggest_fix(word)
                if fix:
                    findings['estado'].append({
                        'original': estado,
                        'word': word,
                        'suggested_fix': fix,
                        'count': count
                    })
        
        # 3. Check document titles
        print("3️⃣ Checking document titles for location names...")
        cursor.execute("""
            SELECT id, titulo
            FROM documents 
            WHERE titulo ~ '[a-z][A-Z]'
               OR titulo ~ '^[A-Z][a-z]+[A-Z]'
            LIMIT 100
        """)
        
        titles = cursor.fetchall()
        title_patterns = defaultdict(int)
        
        for id, titulo in titles:
            camelcase_words = find_camelcase_pattern(titulo)
            for word in camelcase_words:
                # Focus on words that look like place names (capitalized, longer than 5 chars)
                if len(word) > 5 and word[0].isupper():
                    fix = suggest_fix(word)
                    if fix:
                        title_patterns[f"{word} → {fix}"] += 1
        
        # 4. Check content field for municipality names
        print("4️⃣ Sampling content field...")
        cursor.execute("""
            SELECT id, conteudo
            FROM documents 
            WHERE conteudo ~ '[a-z][A-Z]'
            LIMIT 50
        """)
        
        contents = cursor.fetchall()
        content_patterns = defaultdict(int)
        
        for id, content in contents:
            if content:
                camelcase_words = find_camelcase_pattern(content[:500])  # Check first 500 chars
                for word in camelcase_words:
                    if len(word) > 5 and word[0].isupper():
                        fix = suggest_fix(word)
                        if fix:
                            content_patterns[f"{word} → {fix}"] += 1
        
        # Print findings
        print("\n📊 FINDINGS SUMMARY:")
        
        if findings['municipality']:
            print(f"\n🏘️ Municipality field: {len(findings['municipality'])} issues found")
            for item in findings['municipality']:
                print(f"   '{item['word']}' → '{item['suggested_fix']}' ({item['count']} records)")
                print(f"      Full value: '{item['original']}'")
        
        if findings['estado']:
            print(f"\n🗺️ Estado field: {len(findings['estado'])} issues found")
            for item in findings['estado']:
                print(f"   '{item['word']}' → '{item['suggested_fix']}' ({item['count']} records)")
        
        if title_patterns:
            print(f"\n📄 Common patterns in titles:")
            sorted_patterns = sorted(title_patterns.items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:10]:
                print(f"   {pattern} (found {count} times)")
        
        if content_patterns:
            print(f"\n📝 Common patterns in content:")
            sorted_patterns = sorted(content_patterns.items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns[:10]:
                print(f"   {pattern} (found {count} times)")
        
        # Generate fix recommendations
        print("\n💡 RECOMMENDED FIXES:")
        all_fixes = set()
        
        for field_findings in findings.values():
            for item in field_findings:
                all_fixes.add((item['word'], item['suggested_fix']))
        
        print(f"\nUnique camelCase patterns to fix: {len(all_fixes)}")
        for original, fixed in sorted(all_fixes):
            print(f"   {original} → {fixed}")
        
        conn.close()
        return findings
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return {}

if __name__ == "__main__":
    findings = analyze_database()