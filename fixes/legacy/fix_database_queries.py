#!/usr/bin/env python3
"""
Fix the database queries in database_connection.R to include municipality column
"""

import re

def fix_database_queries():
    """Fix all queries in database_connection.R to include municipality column"""
    
    # Read the file
    with open('scripts/R/database_connection.R', 'r') as f:
        content = f.read()
    
    # Fix pattern 1: Replace "'' as municipio," with "COALESCE(municipality, '') as municipio,"
    content = re.sub(
        r"''\s*as\s+municipio,",
        "COALESCE(municipality, '') as municipio,",
        content
    )
    
    # Fix pattern 2: Add missing columns to SELECT statements that only have basic columns
    # This is for the limited queries and fallback queries
    
    # Find SELECT statements with basic columns and add the missing ones
    basic_select_pattern = r'(SELECT\s+\n?\s*id,\s*\n?\s*titulo,\s*\n?\s*tipo,\s*\n?\s*estado,\s*\n?\s*estado as estado_codigo,\s*\n?\s*COALESCE\(municipality, \'\'\) as municipio,\s*\n?\s*COALESCE\([^,]+\) as enacting_date,\s*\n?\s*url,\s*\n?\s*urn)(\s*\n?\s*FROM)'
    
    def add_missing_columns(match):
        select_part = match.group(1)
        from_part = match.group(2)
        
        # Add missing columns if they're not already there
        if 'conteudo' not in select_part:
            select_part += ',\n              conteudo,\n              document_summary,\n              document_type_full,\n              search_term'
        
        return select_part + from_part
    
    content = re.sub(basic_select_pattern, add_missing_columns, content, flags=re.MULTILINE | re.DOTALL)
    
    # Write the fixed content back
    with open('scripts/R/database_connection.R', 'w') as f:
        f.write(content)
    
    print("✅ Fixed database queries to include municipality and other essential columns")
    return True

if __name__ == "__main__":
    fix_database_queries()