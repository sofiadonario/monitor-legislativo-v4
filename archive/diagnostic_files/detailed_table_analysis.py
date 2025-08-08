#!/usr/bin/env python3
"""
Detailed Table Structure Analysis for Legislative Monitoring Database
"""

import psycopg2
import json
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
    print("=== DETAILED TABLE STRUCTURE ANALYSIS ===")
    print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Get complete structure of documents table
        print("1. DOCUMENTS TABLE - COMPLETE STRUCTURE")
        print("=" * 40)
        
        cursor.execute("""
            SELECT 
                column_name,
                data_type,
                is_nullable,
                column_default,
                character_maximum_length,
                numeric_precision,
                numeric_scale,
                ordinal_position
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'documents'
            ORDER BY ordinal_position;
        """)
        
        docs_columns = cursor.fetchall()
        print(f"Documents table has {len(docs_columns)} columns:\n")
        
        for col in docs_columns:
            name, dtype, nullable, default, max_len, precision, scale, pos = col
            type_info = dtype
            if max_len:
                type_info += f"({max_len})"
            elif precision:
                type_info += f"({precision},{scale or 0})"
            
            null_info = "NULL" if nullable == "YES" else "NOT NULL"
            default_info = f" DEFAULT {str(default)[:30]}..." if default else ""
            
            print(f"  {pos:2d}. {name:<25} {type_info:<20} {null_info:<8} {default_info}")
        
        # Sample data from documents table
        print(f"\n2. SAMPLE DATA FROM DOCUMENTS TABLE")
        print("=" * 35)
        
        cursor.execute("SELECT * FROM documents LIMIT 3;")
        sample_docs = cursor.fetchall()
        
        # Get column names for reference
        column_names = [desc[0] for desc in cursor.description]
        
        print("Column names:")
        for i, name in enumerate(column_names):
            print(f"  {i+1:2d}. {name}")
        
        print(f"\nFirst 3 documents (showing key fields only):")
        key_fields = ['id', 'titulo', 'tipo', 'numero', 'data', 'autor', 'urn', 'ementa']
        key_indices = [column_names.index(field) for field in key_fields if field in column_names]
        
        print("Key fields:", " | ".join(key_fields))
        print("-" * 100)
        
        for doc in sample_docs:
            values = []
            for idx in key_indices:
                value = str(doc[idx]) if doc[idx] is not None else "NULL"
                values.append(value[:15] + "..." if len(value) > 15 else value)
            print(" | ".join(f"{v:<15}" for v in values))
        
        # Data quality analysis
        print(f"\n3. DATA QUALITY ANALYSIS")
        print("=" * 24)
        
        # Check for null values in key fields
        null_checks = [
            ('titulo', 'Title'),
            ('tipo', 'Document Type'),
            ('data', 'Date'),
            ('urn', 'URN'),
            ('ementa', 'Summary'),
            ('autor', 'Author')
        ]
        
        for field, description in null_checks:
            cursor.execute(f"SELECT COUNT(*) FROM documents WHERE {field} IS NULL;")
            null_count = cursor.fetchone()[0]
            cursor.execute(f"SELECT COUNT(*) FROM documents WHERE {field} = '';")
            empty_count = cursor.fetchone()[0]
            total_null = null_count + empty_count
            
            print(f"{description:<15}: {total_null:>6,} null/empty ({total_null/134014*100:.1f}%)")
        
        # Date range analysis
        print(f"\n4. DATE RANGE ANALYSIS")
        print("=" * 22)
        
        cursor.execute("""
            SELECT 
                MIN(data) as min_date,
                MAX(data) as max_date,
                COUNT(DISTINCT data) as unique_dates,
                COUNT(*) as total_with_dates
            FROM documents 
            WHERE data IS NOT NULL;
        """)
        
        date_stats = cursor.fetchone()
        if date_stats:
            min_date, max_date, unique_dates, total_with_dates = date_stats
            print(f"Date range: {min_date} to {max_date}")
            print(f"Documents with dates: {total_with_dates:,}")
            print(f"Unique dates: {unique_dates:,}")
        
        # Document type analysis
        print(f"\n5. DOCUMENT TYPE ANALYSIS")
        print("=" * 25)
        
        cursor.execute("""
            SELECT 
                tipo,
                COUNT(*) as count,
                ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
            FROM documents 
            WHERE tipo IS NOT NULL
            GROUP BY tipo
            ORDER BY count DESC
            LIMIT 15;
        """)
        
        doc_types = cursor.fetchall()
        print("Top 15 document types:")
        print(f"{'Type':<30} {'Count':<10} {'%':<8}")
        print("-" * 50)
        for tipo, count, pct in doc_types:
            tipo_display = tipo[:28] if tipo else "NULL"
            print(f"{tipo_display:<30} {count:<10,} {pct:<8}")
        
        # Author analysis
        print(f"\n6. AUTHOR ANALYSIS")
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
        print(f"\nTop 10 authors by document count:")
        for author, count in top_authors:
            author_display = author[:40] if author else "NULL"
            print(f"  {author_display:<40} {count:>6,}")
        
        # Analyze views
        print(f"\n7. DASHBOARD VIEWS ANALYSIS")
        print("=" * 27)
        
        views_to_analyze = [
            'dashboard_summary',
            'documents_by_category', 
            'documents_by_state',
            'documents_by_transport',
            'lexml_dashboard_view'
        ]
        
        for view_name in views_to_analyze:
            print(f"\n--- View: {view_name} ---")
            
            # Get view structure
            cursor.execute(f"""
                SELECT 
                    column_name,
                    data_type
                FROM information_schema.columns 
                WHERE table_schema = 'public' AND table_name = '{view_name}'
                ORDER BY ordinal_position;
            """)
            
            view_columns = cursor.fetchall()
            if view_columns:
                print("Columns:")
                for col_name, col_type in view_columns:
                    print(f"  - {col_name}: {col_type}")
                
                # Get row count and sample data
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {view_name};")
                    row_count = cursor.fetchone()[0]
                    print(f"Row count: {row_count:,}")
                    
                    cursor.execute(f"SELECT * FROM {view_name} LIMIT 3;")
                    sample_data = cursor.fetchall()
                    if sample_data:
                        print("Sample rows:")
                        for i, row in enumerate(sample_data, 1):
                            row_display = " | ".join(str(val)[:20] if val is not None else "NULL" for val in row)
                            print(f"  {i}. {row_display}")
                
                except Exception as e:
                    print(f"  Error querying view: {e}")
        
        # Check for indexes
        print(f"\n8. INDEX ANALYSIS")
        print("=" * 17)
        
        cursor.execute("""
            SELECT 
                schemaname,
                tablename,
                indexname,
                indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
            ORDER BY tablename, indexname;
        """)
        
        indexes = cursor.fetchall()
        if indexes:
            current_table = ""
            for schema, table, index_name, index_def in indexes:
                if table != current_table:
                    print(f"\nTable: {table}")
                    current_table = table
                print(f"  - {index_name}")
                print(f"    {index_def}")
        
        # Foreign key relationships
        print(f"\n9. FOREIGN KEY RELATIONSHIPS")
        print("=" * 28)
        
        cursor.execute("""
            SELECT
                tc.table_name,
                kcu.column_name,
                ccu.table_name AS foreign_table_name,
                ccu.column_name AS foreign_column_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
                AND ccu.table_schema = tc.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_schema = 'public';
        """)
        
        foreign_keys = cursor.fetchall()
        if foreign_keys:
            print("Foreign key relationships:")
            for table, column, ref_table, ref_column in foreign_keys:
                print(f"  {table}.{column} -> {ref_table}.{ref_column}")
        else:
            print("No foreign key relationships found.")
        
        print(f"\n=== DETAILED ANALYSIS COMPLETE ===")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    main()