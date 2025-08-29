#!/usr/bin/env python3
"""
Export full dataset from Railway PostgreSQL database to CSV for local testing
"""

import psycopg2
import pandas as pd
import sys
from datetime import datetime

# Database connection parameters
DB_PARAMS = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def export_documents():
    """Export documents from database to CSV"""
    try:
        print("Connecting to Railway database...")
        conn = psycopg2.connect(**DB_PARAMS)
        
        # Query to get all documents
        query = """
        SELECT 
            id,
            titulo as title,
            tipo as type,
            species,
            estado as state,
            estado_codigo as state_code,
            municipality,
            data_publicacao as publication_date,
            url,
            urn,
            conteudo as content,
            document_summary as summary,
            document_type_full,
            search_term,
            autor as author,
            fonte as source,
            transport_category as category,
            created_at,
            updated_at,
            locality,
            authority,
            authority_level,
            document_number,
            justice,
            region,
            court_class,
            document_description,
            metadata
        FROM documents
        ORDER BY data_publicacao DESC
        """
        
        print("Fetching documents from database...")
        df = pd.read_sql_query(query, conn)
        
        print(f"Retrieved {len(df)} documents")
        
        # Save to CSV
        filename = f"lexml_unified_dataset_{datetime.now().strftime('%Y%m%d')}.csv"
        print(f"Saving to {filename}...")
        df.to_csv(filename, index=False)
        
        print(f"Successfully exported {len(df)} documents to {filename}")
        
        # Also create a smaller sample for quick testing
        sample_filename = "lexml_sample_for_railway.csv"
        df.head(20000).to_csv(sample_filename, index=False)
        print(f"Created sample file with 20,000 documents: {sample_filename}")
        
        conn.close()
        return filename
        
    except psycopg2.OperationalError as e:
        print(f"Database connection failed: {e}")
        print("\nTrying alternative approach with pg_dump...")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    export_documents()