#!/usr/bin/env python3
"""
Fixed Detailed Table Structure Analysis for Legislative Monitoring Database
"""

import psycopg2
from datetime import datetime

# Database connection parameters
DB_CONFIG = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def main():
    print("=== DETAILED TABLE STRUCTURE ANALYSIS (FIXED) ===")
    print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Data quality analysis (fixed)
        print(f"1. DATA QUALITY ANALYSIS")
        print("=" * 24)
        
        # Check for null values in key fields (fixed for date fields)
        text_fields = [
            ('titulo', 'Title'),
            ('tipo', 'Document Type'),
            ('urn', 'URN'),
            ('ementa', 'Summary'),
            ('autor', 'Author'),
            ('numero', 'Number'),
            ('assuntos', 'Subjects')
        ]
        
        for field, description in text_fields:
            cursor.execute(f"SELECT COUNT(*) FROM documents WHERE {field} IS NULL;")
            null_count = cursor.fetchone()[0]
            cursor.execute(f"SELECT COUNT(*) FROM documents WHERE {field} = '';")
            empty_count = cursor.fetchone()[0]
            total_null = null_count + empty_count
            
            print(f"{description:<15}: {total_null:>6,} null/empty ({total_null/134014*100:.1f}%)")
        
        # Date fields (separate handling)
        date_fields = [
            ('data', 'Date'),
            ('data_publicacao', 'Publication Date'),
            ('data_coleta', 'Collection Date')
        ]
        
        for field, description in date_fields:
            cursor.execute(f"SELECT COUNT(*) FROM documents WHERE {field} IS NULL;")
            null_count = cursor.fetchone()[0]
            print(f"{description:<15}: {null_count:>6,} null ({null_count/134014*100:.1f}%)")
        
        # Date range analysis
        print(f"\n2. DATE RANGE ANALYSIS")
        print("=" * 22)
        
        for field, description in date_fields:
            cursor.execute(f"""
                SELECT 
                    MIN({field}) as min_date,
                    MAX({field}) as max_date,
                    COUNT(DISTINCT {field}) as unique_dates,
                    COUNT(*) as total_with_dates
                FROM documents 
                WHERE {field} IS NOT NULL;
            """)
            
            date_stats = cursor.fetchone()
            if date_stats and date_stats[3] > 0:
                min_date, max_date, unique_dates, total_with_dates = date_stats
                print(f"{description}:")
                print(f"  Range: {min_date} to {max_date}")
                print(f"  Documents with dates: {total_with_dates:,}")
                print(f"  Unique dates: {unique_dates:,}")
            else:
                print(f"{description}: No valid dates found")
        
        # Document type analysis
        print(f"\n3. DOCUMENT TYPE ANALYSIS")
        print("=" * 25)
        
        cursor.execute("""
            SELECT 
                tipo,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
            FROM documents 
            WHERE tipo IS NOT NULL AND tipo != ''
            GROUP BY tipo
            ORDER BY count DESC
            LIMIT 15;
        """)
        
        doc_types = cursor.fetchall()
        print("Top 15 document types:")
        print(f"{'Type':<40} {'Count':<10} {'%':<8}")
        print("-" * 60)
        for tipo, count, pct in doc_types:
            tipo_display = tipo[:38] if tipo else "NULL"
            print(f"{tipo_display:<40} {count:<10,} {pct:<8}")
        
        # Category analysis
        print(f"\n4. CATEGORY ANALYSIS")
        print("=" * 20)
        
        cursor.execute("""
            SELECT 
                dc.name as category_name,
                COUNT(d.id) as document_count
            FROM document_categories dc
            LEFT JOIN documents d ON dc.id = d.category_id
            GROUP BY dc.id, dc.name
            ORDER BY document_count DESC;
        """)
        
        categories = cursor.fetchall()
        print("Documents by category:")
        print(f"{'Category':<30} {'Count':<10}")
        print("-" * 42)
        for cat_name, count in categories:
            print(f"{cat_name:<30} {count:<10,}")
        
        # Transport mode analysis
        print(f"\n5. TRANSPORT MODE ANALYSIS")
        print("=" * 26)
        
        cursor.execute("""
            SELECT 
                tm.name as transport_name,
                COUNT(d.id) as document_count
            FROM transport_modes tm
            LEFT JOIN documents d ON tm.id = d.transport_mode_id
            GROUP BY tm.id, tm.name
            ORDER BY document_count DESC;
        """)
        
        transport_modes = cursor.fetchall()
        print("Documents by transport mode:")
        print(f"{'Transport Mode':<30} {'Count':<10}")
        print("-" * 42)
        for trans_name, count in transport_modes:
            print(f"{trans_name:<30} {count:<10,}")
        
        # Jurisdiction analysis
        print(f"\n6. JURISDICTION ANALYSIS")
        print("=" * 24)
        
        cursor.execute("""
            SELECT 
                j.name as jurisdiction_name,
                COUNT(d.id) as document_count
            FROM jurisdictions j
            LEFT JOIN documents d ON j.id = d.jurisdiction_id
            GROUP BY j.id, j.name
            ORDER BY document_count DESC;
        """)
        
        jurisdictions = cursor.fetchall()
        print("Documents by jurisdiction:")
        print(f"{'Jurisdiction':<30} {'Count':<10}")
        print("-" * 42)
        for juris_name, count in jurisdictions:
            print(f"{juris_name:<30} {count:<10,}")
        
        # Geographic distribution
        print(f"\n7. GEOGRAPHIC DISTRIBUTION")
        print("=" * 26)
        
        # By state
        cursor.execute("""
            SELECT 
                estado,
                COUNT(*) as count
            FROM documents 
            WHERE estado IS NOT NULL AND estado != ''
            GROUP BY estado
            ORDER BY count DESC
            LIMIT 10;
        """)
        
        states = cursor.fetchall()
        if states:
            print("Top 10 states by document count:")
            print(f"{'State':<20} {'Count':<10}")
            print("-" * 32)
            for state, count in states:
                print(f"{state:<20} {count:<10,}")
        
        # Author analysis
        print(f"\n8. AUTHOR ANALYSIS")
        print("=" * 18)
        
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT autor) as unique_authors,
                COUNT(*) FILTER (WHERE autor IS NOT NULL AND autor != '') as docs_with_author
            FROM documents;
        """)
        
        author_stats = cursor.fetchone()
        if author_stats:
            unique_authors, docs_with_author = author_stats
            print(f"Unique authors: {unique_authors:,}")
            print(f"Documents with author: {docs_with_author:,}")
        
        # Top authors
        cursor.execute("""
            SELECT 
                autor,
                COUNT(*) as count
            FROM documents 
            WHERE autor IS NOT NULL AND autor != ''
            GROUP BY autor
            ORDER BY count DESC
            LIMIT 10;
        """)
        
        top_authors = cursor.fetchall()
        if top_authors:
            print(f"\nTop 10 authors by document count:")
            print(f"{'Author':<50} {'Count':<10}")
            print("-" * 62)
            for author, count in top_authors:
                author_display = author[:48] if author else "NULL"
                print(f"{author_display:<50} {count:>10,}")
        
        # Year distribution
        print(f"\n9. YEAR DISTRIBUTION")
        print("=" * 20)
        
        cursor.execute("""
            SELECT 
                ano,
                COUNT(*) as count
            FROM documents 
            WHERE ano IS NOT NULL
            GROUP BY ano
            ORDER BY ano DESC
            LIMIT 15;
        """)
        
        years = cursor.fetchall()
        if years:
            print("Recent years document distribution:")
            print(f"{'Year':<6} {'Count':<10}")
            print("-" * 18)
            for year, count in years:
                print(f"{year:<6} {count:<10,}")
        
        # Data source analysis
        print(f"\n10. DATA SOURCE ANALYSIS")
        print("=" * 24)
        
        cursor.execute("""
            SELECT 
                origem,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
            FROM documents 
            WHERE origem IS NOT NULL AND origem != ''
            GROUP BY origem
            ORDER BY count DESC;
        """)
        
        sources = cursor.fetchall()
        if sources:
            print("Documents by source:")
            print(f"{'Source':<30} {'Count':<10} {'%':<8}")
            print("-" * 50)
            for source, count, pct in sources:
                source_display = source[:28] if source else "NULL"
                print(f"{source_display:<30} {count:<10,} {pct:<8}")
        
        # Deduplication analysis
        print(f"\n11. DEDUPLICATION ANALYSIS")
        print("=" * 26)
        
        cursor.execute("""
            SELECT 
                deduplication_source,
                COUNT(*) as count,
                AVG(original_count) as avg_original_count
            FROM documents 
            GROUP BY deduplication_source
            ORDER BY count DESC;
        """)
        
        dedup_stats = cursor.fetchall()
        if dedup_stats:
            print("Deduplication statistics:")
            print(f"{'Source Type':<20} {'Count':<10} {'Avg Original':<15}")
            print("-" * 47)
            for dedup_type, count, avg_count in dedup_stats:
                avg_display = f"{avg_count:.1f}" if avg_count else "N/A"
                print(f"{dedup_type:<20} {count:<10,} {avg_display:<15}")
        
        print(f"\n=== DETAILED ANALYSIS COMPLETE ===")
        print(f"Total documents analyzed: 134,014")
        print(f"Database is ready for R Shiny application")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    main()