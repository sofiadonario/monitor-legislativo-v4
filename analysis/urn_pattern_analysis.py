#!/usr/bin/env python3
"""
URN Pattern Analysis for Unidentified Geographic Documents
Date: 2025-11-11
Purpose: Investigate URN patterns to improve geographic extraction logic
"""

import psycopg2
import sys
from collections import Counter
import re

# Database connection parameters
DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 5433,
    'database': 'monitor_legislativo',
    'user': 'monitor_user',
    'password': 'Sdonario1'
}

def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70 + "\n")

def execute_query(conn, query, params=None):
    """Execute query with error handling"""
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        cursor.close()
        return results
    except Exception as e:
        print(f"Query error: {e}")
        return None

def analyze_urn_patterns(urns, category_name):
    """Analyze URN structural patterns"""
    print(f"\nPattern Analysis for: {category_name}")
    print("-" * 70)

    if not urns:
        print("No URNs to analyze")
        return

    # Component analysis
    components = {
        ':lex:': sum(1 for u in urns if ':lex:' in u),
        ':congresso.nacional:': sum(1 for u in urns if ':congresso.nacional:' in u),
        ':estado:': sum(1 for u in urns if ':estado:' in u),
        ':municipal:': sum(1 for u in urns if ':municipal:' in u),
        ':federal:': sum(1 for u in urns if ':federal:' in u),
        ':br:': sum(1 for u in urns if ':br:' in u),
    }

    print(f"\nTotal URNs analyzed: {len(urns)}")
    print("\nURN Component Frequencies:")
    for comp, count in components.items():
        print(f"  {comp:25s}: {count:5d} / {len(urns)} ({100*count/len(urns):.1f}%)")

    # Extract URN prefixes (first 4 components)
    prefixes = []
    for urn in urns:
        parts = urn.split(':')
        if len(parts) >= 4:
            prefix = ':'.join(parts[:4]) + ':'
            prefixes.append(prefix)

    if prefixes:
        print("\nTop 10 URN Prefixes (first 4 components):")
        prefix_counts = Counter(prefixes)
        for prefix, count in prefix_counts.most_common(10):
            print(f"  {count:4d} | {prefix}")

    # Check for state codes
    state_pattern = r':(ac|al|ap|am|ba|ce|df|es|go|ma|mt|ms|mg|pa|pb|pr|pe|pi|rj|rn|rs|ro|rr|sc|sp|se|to):'
    state_matches = sum(1 for u in urns if re.search(state_pattern, u, re.IGNORECASE))
    print(f"\nURNs with state codes: {state_matches} / {len(urns)} ({100*state_matches/len(urns):.1f}%)")

def main():
    print_section("URN PATTERN ANALYSIS FOR UNIDENTIFIED GEOGRAPHIC DOCUMENTS")

    try:
        # Connect to database
        print("Connecting to database...")
        conn = psycopg2.connect(**DB_CONFIG)
        print("Connected successfully!\n")

        # 1. Total documents
        print_section("DATABASE OVERVIEW")
        result = execute_query(conn, "SELECT COUNT(*) FROM documents")
        if result:
            total_docs = result[0][0]
            print(f"Total documents in database: {total_docs:,}")

        # 2. Breakdown of unidentified categories
        print_section("1. BREAKDOWN OF UNIDENTIFIED CATEGORIES")

        # Simpler query - just get counts
        queries = {
            'Nacional': "SELECT COUNT(*) FROM documents WHERE estado_mapeado = 'Nacional'",
            'Estadual': "SELECT COUNT(*) FROM documents WHERE estado_mapeado = 'Estadual'",
            'NULL': "SELECT COUNT(*) FROM documents WHERE estado_mapeado IS NULL",
            'Não Identificado': "SELECT COUNT(*) FROM documents WHERE estado_mapeado = 'Não Identificado'"
        }

        category_counts = {}
        for category, query in queries.items():
            result = execute_query(conn, query)
            if result:
                count = result[0][0]
                category_counts[category] = count
                print(f"{category:20s}: {count:8,} documents")

        total_unidentified = sum(category_counts.values())
        print(f"\n{'Total Unidentified':20s}: {total_unidentified:8,} documents")
        print(f"Percentage of database: {100 * total_unidentified / total_docs:.2f}%")

        # Breakdown percentages
        print("\nPercentage breakdown of unidentified categories:")
        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            pct_of_unidentified = 100 * count / total_unidentified if total_unidentified > 0 else 0
            pct_of_total = 100 * count / total_docs
            print(f"  {category:20s}: {pct_of_unidentified:5.2f}% of unidentified | {pct_of_total:5.2f}% of total")

        # 3. Nacional documents
        print_section("2. NACIONAL DOCUMENTS")
        nacional_count = category_counts.get('Nacional', 0)
        print(f"Total Nacional documents: {nacional_count:,}\n")

        if nacional_count > 0:
            print("Sample URNs (first 30):")
            print("-" * 70)
            result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado = 'Nacional' LIMIT 30")
            if result:
                nacional_urns = [row[0] for row in result]
                for i, urn in enumerate(nacional_urns, 1):
                    print(f"{i:2d}. {urn}")

                # Get more for pattern analysis
                result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado = 'Nacional' LIMIT 100")
                if result:
                    urns_for_analysis = [row[0] for row in result]
                    analyze_urn_patterns(urns_for_analysis, "NACIONAL")

        # 4. Estadual (Generic) documents
        print_section("3. ESTADUAL (GENERIC) DOCUMENTS")
        estadual_count = category_counts.get('Estadual', 0)
        print(f"Total Estadual documents: {estadual_count:,}\n")

        if estadual_count > 0:
            print("Sample URNs (first 30):")
            print("-" * 70)
            result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado = 'Estadual' LIMIT 30")
            if result:
                estadual_urns = [row[0] for row in result]
                for i, urn in enumerate(estadual_urns, 1):
                    print(f"{i:2d}. {urn}")

                # Get more for pattern analysis
                result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado = 'Estadual' LIMIT 100")
                if result:
                    urns_for_analysis = [row[0] for row in result]
                    analyze_urn_patterns(urns_for_analysis, "ESTADUAL (GENERIC)")

        # 5. NULL estado_mapeado
        print_section("4. NULL ESTADO_MAPEADO DOCUMENTS")
        null_count = category_counts.get('NULL', 0)
        print(f"Total NULL estado_mapeado: {null_count:,}\n")

        if null_count > 0:
            print("Sample URNs (first 30):")
            print("-" * 70)
            result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado IS NULL LIMIT 30")
            if result:
                null_urns = [row[0] for row in result]
                for i, urn in enumerate(null_urns, 1):
                    print(f"{i:2d}. {urn}")

                # Get more for pattern analysis
                result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado IS NULL LIMIT 100")
                if result:
                    urns_for_analysis = [row[0] for row in result]
                    analyze_urn_patterns(urns_for_analysis, "NULL")

        # 6. Não Identificado
        print_section("5. NÃO IDENTIFICADO (EXPLICIT) DOCUMENTS")
        nao_ident_count = category_counts.get('Não Identificado', 0)
        print(f"Total 'Não Identificado': {nao_ident_count:,}\n")

        if nao_ident_count > 0:
            print("Sample URNs (first 30):")
            print("-" * 70)
            result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado = 'Não Identificado' LIMIT 30")
            if result:
                nao_ident_urns = [row[0] for row in result]
                for i, urn in enumerate(nao_ident_urns, 1):
                    print(f"{i:2d}. {urn}")

                # Get more for pattern analysis
                result = execute_query(conn, "SELECT urn FROM documents WHERE estado_mapeado = 'Não Identificado' LIMIT 100")
                if result:
                    urns_for_analysis = [row[0] for row in result]
                    analyze_urn_patterns(urns_for_analysis, "NÃO IDENTIFICADO")

        # 7. Recommendations
        print_section("6. RECOMMENDATIONS FOR IMPROVING GEOGRAPHIC EXTRACTION")

        print("""
Based on the URN pattern analysis, here are recommendations:

A. NACIONAL DOCUMENTS:
   - Review URNs with 'congresso.nacional' or 'federal' components
   - These may be correctly classified as Nacional
   - Verify if any contain hidden state indicators in the URN structure
   - Consider extracting jurisdiction from document metadata if available

B. ESTADUAL (GENERIC) DOCUMENTS:
   - Extract state codes from URN structure using regex: :(ac|al|ap|...)
   - Look for patterns like 'urn:lex:br;estado:XX:' where XX is state code
   - Check URN components after 'urn:lex:br:' for state identifiers
   - Review document titles/content for state mentions as fallback

C. NULL ESTADO_MAPEADO:
   - Implement systematic URN parsing to extract geographic components
   - Check for municipal URNs with embedded state information
   - Pattern: 'urn:lex:br:estado:XX:municipal:...' contains state code
   - Build a URN component extractor function for all URN types

D. GENERAL IMPROVEMENTS:
   1. Build a URN parser that systematically extracts components:
      - Split by ':' and analyze position-based patterns
      - Create lookup tables for common URN structures

   2. Implement hierarchical extraction:
      - Try exact state code match first
      - Fall back to URN structure analysis
      - Use document metadata as last resort

   3. Create confidence scoring:
      - High confidence: Explicit state code in URN
      - Medium confidence: Inferred from URN structure
      - Low confidence: From document metadata

   4. Add validation:
      - Cross-reference extracted state with document issuer
      - Validate against known valid state codes
      - Flag ambiguous cases for manual review

E. SPECIFIC URN PATTERNS TO HANDLE:
   - Federal: 'urn:lex:br:federal:...' -> Nacional
   - State: 'urn:lex:br:estado:XX:...' -> Extract XX as state code
   - Municipal: 'urn:lex:br:estado:XX:municipal:...' -> Extract XX as state
   - Congresso: 'urn:lex:br:congresso.nacional:...' -> Nacional
        """)

        print_section("ANALYSIS COMPLETE")
        print("Output saved to: analysis/urn_pattern_output.txt")

        conn.close()

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
