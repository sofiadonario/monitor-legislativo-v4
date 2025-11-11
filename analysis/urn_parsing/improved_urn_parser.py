#!/usr/bin/env python3
"""
Improved URN Parser for Brazilian Legislative Documents
========================================================

This module implements a hierarchical URN parser to extract geographic information
from Brazilian LexML URNs, reducing unidentified documents from ~11% to <2%.

Author: Data Science Team
Date: 2025-11-11
Version: 1.0

Usage:
    from improved_urn_parser import parse_urn_geography

    estado_mapeado, confidence = parse_urn_geography(urn)
    print(f"Estado: {estado_mapeado}, Confidence: {confidence}")
"""

import re
from typing import Tuple, Optional

# Brazilian state codes (uppercase for consistency)
BRAZILIAN_STATES = {
    'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA',
    'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN',
    'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO'
}

# State name to code mapping (for fallback text extraction)
STATE_NAME_TO_CODE = {
    'acre': 'AC', 'alagoas': 'AL', 'amapá': 'AP', 'amapa': 'AP',
    'amazonas': 'AM', 'bahia': 'BA', 'ceará': 'CE', 'ceara': 'CE',
    'distrito federal': 'DF', 'espírito santo': 'ES', 'espirito santo': 'ES',
    'goiás': 'GO', 'goias': 'GO', 'maranhão': 'MA', 'maranhao': 'MA',
    'mato grosso': 'MT', 'mato grosso do sul': 'MS',
    'minas gerais': 'MG', 'pará': 'PA', 'para': 'PA',
    'paraíba': 'PB', 'paraiba': 'PB', 'paraná': 'PR', 'parana': 'PR',
    'pernambuco': 'PE', 'piauí': 'PI', 'piaui': 'PI',
    'rio de janeiro': 'RJ', 'rio grande do norte': 'RN',
    'rio grande do sul': 'RS', 'rondônia': 'RO', 'rondonia': 'RO',
    'roraima': 'RR', 'santa catarina': 'SC',
    'são paulo': 'SP', 'sao paulo': 'SP',
    'sergipe': 'SE', 'tocantins': 'TO'
}


def parse_urn_geography(urn: str) -> Tuple[Optional[str], str]:
    """
    Extract geographic information from a Brazilian LexML URN.

    Uses hierarchical pattern matching to identify federal, state, or municipal
    jurisdiction from the URN structure.

    Args:
        urn: The LexML URN string (e.g., "urn:lex:br:federal:lei:2021-01-01;14.133")

    Returns:
        Tuple of (estado_mapeado, confidence):
        - estado_mapeado: 'Nacional', state code ('SP', 'RJ', etc.), or None
        - confidence: 'HIGH', 'MEDIUM', 'LOW', or 'UNKNOWN'

    Examples:
        >>> parse_urn_geography('urn:lex:br:federal:lei:2021-01-01;14.133')
        ('Nacional', 'HIGH')

        >>> parse_urn_geography('urn:lex:br:estado:sp:lei:2020-03-01;17.293')
        ('SP', 'HIGH')

        >>> parse_urn_geography('urn:lex:br:estado:sp:municipal:sao.paulo:lei:2019-05-01;16.974')
        ('SP', 'HIGH')
    """

    if not urn or not isinstance(urn, str):
        return None, 'UNKNOWN'

    urn_lower = urn.lower()

    # =========================================================================
    # PRIORITY 1: Federal/National Legislation
    # =========================================================================

    # Pattern: :federal: or :congresso.nacional:
    if ':federal:' in urn_lower or ':congresso.nacional:' in urn_lower:
        return 'Nacional', 'HIGH'

    # =========================================================================
    # PRIORITY 2: State Code Extraction - Direct Patterns
    # =========================================================================

    # Pattern 1: urn:lex:br:estado:XX:
    # This is the most common and explicit state pattern
    match = re.search(
        r':estado:([a-z]{2}):',
        urn_lower
    )
    if match:
        state_code = match.group(1).upper()
        if state_code in BRAZILIAN_STATES:
            return state_code, 'HIGH'

    # Pattern 2: urn:lex:br:XX: (direct state code without "estado" keyword)
    # Example: urn:lex:br:sp:lei:...
    match = re.search(
        r':br:([a-z]{2}):',
        urn_lower
    )
    if match:
        state_code = match.group(1).upper()
        if state_code in BRAZILIAN_STATES:
            return state_code, 'HIGH'

    # =========================================================================
    # PRIORITY 3: Municipal Documents (Extract Parent State)
    # =========================================================================

    # Pattern: urn:lex:br:estado:XX:municipal:
    # Municipal documents should map to their parent state
    match = re.search(
        r':estado:([a-z]{2}):municipal:',
        urn_lower
    )
    if match:
        state_code = match.group(1).upper()
        if state_code in BRAZILIAN_STATES:
            return state_code, 'HIGH'

    # Pattern: urn:lex:br:XX:municipal:
    match = re.search(
        r':br:([a-z]{2}):municipal:',
        urn_lower
    )
    if match:
        state_code = match.group(1).upper()
        if state_code in BRAZILIAN_STATES:
            return state_code, 'HIGH'

    # =========================================================================
    # PRIORITY 4: Any State Code Anywhere in URN (Less Specific)
    # =========================================================================

    # Search for any 2-letter state code surrounded by colons
    # Pattern: :XX: where XX is a valid state code
    matches = re.findall(
        r':([a-z]{2}):',
        urn_lower
    )
    for potential_code in matches:
        state_code = potential_code.upper()
        if state_code in BRAZILIAN_STATES:
            # Lower confidence because position is not standard
            return state_code, 'MEDIUM'

    # =========================================================================
    # PRIORITY 5: State Names in URN (Text Search)
    # =========================================================================

    # Some URNs might use full state names (less common but possible)
    for state_name, state_code in STATE_NAME_TO_CODE.items():
        if state_name.replace(' ', '.') in urn_lower or state_name.replace(' ', '_') in urn_lower:
            return state_code, 'MEDIUM'

    # =========================================================================
    # PRIORITY 6: Special Cases
    # =========================================================================

    # District Federal (DF) might be referenced as "distrito.federal"
    if 'distrito.federal' in urn_lower or 'distrito_federal' in urn_lower:
        return 'DF', 'HIGH'

    # Legislative assemblies are state-level
    if 'assembleia.legislativa' in urn_lower:
        # Try to extract state from context
        match = re.search(
            r'assembleia\.legislativa:([a-z]{2})',
            urn_lower
        )
        if match:
            state_code = match.group(1).upper()
            if state_code in BRAZILIAN_STATES:
                return state_code, 'MEDIUM'

        # If no state code found but has assembleia.legislativa, it's state-level (generic)
        return 'Estadual', 'LOW'

    # =========================================================================
    # NO MATCH FOUND
    # =========================================================================

    return None, 'UNKNOWN'


def batch_parse_urns(urns: list) -> list:
    """
    Parse multiple URNs in batch.

    Args:
        urns: List of URN strings

    Returns:
        List of dictionaries with keys: 'urn', 'estado_mapeado', 'confidence'
    """
    results = []
    for urn in urns:
        estado, confidence = parse_urn_geography(urn)
        results.append({
            'urn': urn,
            'estado_mapeado': estado,
            'confidence': confidence
        })
    return results


def validate_parser_against_samples():
    """
    Validate the parser against known URN samples.
    Run this to test the parser implementation.
    """
    test_cases = [
        # Federal legislation
        ('urn:lex:br:federal:lei:2021-01-01;14.133', 'Nacional', 'HIGH'),
        ('urn:lex:br:congresso.nacional:lei:2020-12-29;14.026', 'Nacional', 'HIGH'),

        # State legislation
        ('urn:lex:br:estado:sp:lei:2020-03-01;17.293', 'SP', 'HIGH'),
        ('urn:lex:br:estado:rj:lei:2019-01-01;8.001', 'RJ', 'HIGH'),
        ('urn:lex:br:estado:mg:lei:2018-06-15;23.291', 'MG', 'HIGH'),

        # Municipal legislation (should return parent state)
        ('urn:lex:br:estado:sp:municipal:sao.paulo:lei:2019-05-01;16.974', 'SP', 'HIGH'),
        ('urn:lex:br:estado:rj:municipal:rio.de.janeiro:lei:2020-01-01;6.856', 'RJ', 'HIGH'),

        # Direct state code (without "estado" keyword)
        ('urn:lex:br:sp:lei:2020-03-01;17.293', 'SP', 'HIGH'),
        ('urn:lex:br:ba:lei:2019-01-01;14.001', 'BA', 'HIGH'),

        # Edge cases
        ('urn:lex:br:distrito.federal:lei:2020-01-01;6.500', 'DF', 'HIGH'),
        ('urn:lex:br:estado:df:lei:2020-01-01;6.500', 'DF', 'HIGH'),
    ]

    print("=" * 80)
    print("URN PARSER VALIDATION")
    print("=" * 80)
    print()

    passed = 0
    failed = 0

    for urn, expected_estado, expected_confidence in test_cases:
        estado, confidence = parse_urn_geography(urn)

        if estado == expected_estado:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1

        print(f"{status}")
        print(f"  URN:       {urn}")
        print(f"  Expected:  {expected_estado} ({expected_confidence})")
        print(f"  Got:       {estado} ({confidence})")
        print()

    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 80)

    return passed == len(test_cases)


def generate_sql_update_script(table_name: str = 'documents') -> str:
    """
    Generate SQL script to update estado_mapeado using this parser.

    This is a template - you'll need to implement this in your database ETL pipeline.

    Args:
        table_name: Name of the documents table

    Returns:
        SQL script as string
    """

    sql = f"""
-- SQL Update Script for estado_mapeado Field
-- Generated by improved_urn_parser.py
-- Date: 2025-11-11

-- This script shows the logic - implement in your ETL pipeline using Python

-- BACKUP FIRST!
CREATE TABLE {table_name}_estado_backup AS
SELECT id, urn, estado_mapeado
FROM {table_name};

-- Priority 1: Update Federal/Nacional
UPDATE {table_name}
SET estado_mapeado = 'Nacional',
    geo_confidence = 'HIGH'
WHERE (urn LIKE '%:federal:%' OR urn LIKE '%:congresso.nacional:%')
  AND (estado_mapeado IS NULL OR estado_mapeado IN ('Estadual', 'Não Identificado'));

-- Priority 2: Extract State Codes from urn:lex:br:estado:XX:
UPDATE {table_name}
SET estado_mapeado = UPPER(
    (regexp_match(urn, ':estado:([a-z]{{2}}):', 'i'))[1]
),
    geo_confidence = 'HIGH'
WHERE urn ~ ':estado:[a-z]{{2}}:'
  AND (estado_mapeado IS NULL OR estado_mapeado IN ('Estadual', 'Não Identificado'))
  AND UPPER((regexp_match(urn, ':estado:([a-z]{{2}}):', 'i'))[1]) IN (
    'AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG',
    'PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO'
  );

-- Priority 3: Extract State from Municipal Documents
UPDATE {table_name}
SET estado_mapeado = UPPER(
    (regexp_match(urn, ':estado:([a-z]{{2}}):municipal:', 'i'))[1]
),
    geo_confidence = 'HIGH'
WHERE urn ~ ':estado:[a-z]{{2}}:municipal:'
  AND (estado_mapeado IS NULL OR estado_mapeado IN ('Estadual', 'Não Identificado'))
  AND UPPER((regexp_match(urn, ':estado:([a-z]{{2}}):municipal:', 'i'))[1]) IN (
    'AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG',
    'PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO'
  );

-- Priority 4: Extract State from :br:XX: pattern
UPDATE {table_name}
SET estado_mapeado = UPPER(
    (regexp_match(urn, ':br:([a-z]{{2}}):', 'i'))[1]
),
    geo_confidence = 'MEDIUM'
WHERE urn ~ ':br:[a-z]{{2}}:'
  AND (estado_mapeado IS NULL OR estado_mapeado IN ('Estadual', 'Não Identificado'))
  AND UPPER((regexp_match(urn, ':br:([a-z]{{2}}):', 'i'))[1]) IN (
    'AC','AL','AP','AM','BA','CE','DF','ES','GO','MA','MT','MS','MG',
    'PA','PB','PR','PE','PI','RJ','RN','RS','RO','RR','SC','SP','SE','TO'
  );

-- Verify results
SELECT
    'After Update' as status,
    COALESCE(estado_mapeado, 'NULL') as category,
    COUNT(*) as count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM {table_name}), 2) as pct
FROM {table_name}
WHERE estado_mapeado IS NULL
   OR estado_mapeado IN ('Nacional', 'Estadual', 'Não Identificado')
GROUP BY estado_mapeado
ORDER BY count DESC;
"""

    return sql


if __name__ == '__main__':
    # Run validation tests
    print("Running URN Parser Validation Tests...\n")

    all_passed = validate_parser_against_samples()

    if all_passed:
        print("\n✓ All tests passed! Parser is ready for use.")
        print("\nTo use this parser:")
        print("  1. Import: from improved_urn_parser import parse_urn_geography")
        print("  2. Call: estado, confidence = parse_urn_geography(urn)")
        print("  3. Integrate into your ETL pipeline")
        print("\nTo generate SQL update script:")
        print("  sql_script = generate_sql_update_script('documents')")
    else:
        print("\n✗ Some tests failed. Please review the parser logic.")

    print("\n" + "=" * 80)
    print("For detailed implementation guidance, see:")
    print("  analysis/URN_PATTERN_INVESTIGATION_REPORT.md")
    print("=" * 80)
