#!/usr/bin/env python3
"""
Verify database integration success and generate usage examples
"""

import sqlite3
import pandas as pd
from datetime import datetime

def verify_database_integration():
    """Verify the database integration was successful"""
    db_path = "../data/processed/lexml_database.db"
    
    print("🔍 Verifying Database Integration")
    print("=" * 50)
    
    try:
        conn = sqlite3.connect(db_path)
        
        # Basic statistics
        total_query = "SELECT COUNT(*) as total FROM lexml_documents_corrected"
        total_records = pd.read_sql(total_query, conn).iloc[0]['total']
        
        # Date extraction verification
        date_query = """
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN enacting_date IS NOT NULL AND enacting_date != '' THEN 1 END) as with_dates
        FROM lexml_documents_corrected
        """
        date_stats = pd.read_sql(date_query, conn).iloc[0]
        date_rate = (date_stats['with_dates'] / date_stats['total']) * 100
        
        # Document type distribution
        type_query = """
        SELECT 
            COALESCE(urn_type, 'Unknown') as document_type,
            COUNT(*) as count,
            ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents_corrected), 1) as percentage
        FROM lexml_documents_corrected
        GROUP BY urn_type
        ORDER BY count DESC
        """
        type_distribution = pd.read_sql(type_query, conn)
        
        # Date range analysis
        date_range_query = """
        SELECT 
            MIN(enacting_date) as earliest_date,
            MAX(enacting_date) as latest_date,
            COUNT(DISTINCT substr(enacting_date, 1, 4)) as unique_years
        FROM lexml_documents_corrected
        WHERE enacting_date IS NOT NULL AND enacting_date != ''
        """
        date_range = pd.read_sql(date_range_query, conn).iloc[0]
        
        # Top search terms
        terms_query = """
        SELECT 
            search_term,
            COUNT(*) as document_count
        FROM lexml_documents_corrected
        GROUP BY search_term
        ORDER BY document_count DESC
        LIMIT 10
        """
        top_terms = pd.read_sql(terms_query, conn)
        
        conn.close()
        
        # Display results
        print(f"✅ Database Integration Verification Results:")
        print(f"   📊 Total Records: {total_records:,}")
        print(f"   📅 Date Extraction: {date_rate:.1f}% ({date_stats['with_dates']:,}/{date_stats['total']:,})")
        print(f"   📆 Date Range: {date_range['earliest_date']} to {date_range['latest_date']}")
        print(f"   🗓️  Unique Years: {date_range['unique_years']}")
        
        print(f"\n📋 Document Type Distribution:")
        for _, row in type_distribution.iterrows():
            print(f"   {row['document_type']}: {row['count']:,} ({row['percentage']:.1f}%)")
        
        print(f"\n🔍 Top Performing Search Terms:")
        for _, row in top_terms.head(5).iterrows():
            print(f"   '{row['search_term']}': {row['document_count']} documents")
        
        # Success validation
        success_criteria = {
            'substantial_dataset': total_records >= 1500,
            'high_date_extraction': date_rate >= 95,
            'proper_classification': type_distribution.iloc[0]['document_type'] in ['legislation', 'legislacao'],
            'temporal_coverage': date_range['unique_years'] >= 10
        }
        
        all_success = all(success_criteria.values())
        
        print(f"\n✅ Success Criteria:")
        for criterion, passed in success_criteria.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"   {criterion.replace('_', ' ').title()}: {status}")
        
        if all_success:
            print(f"\n🎉 DATABASE INTEGRATION FULLY SUCCESSFUL!")
            print(f"✅ All quality criteria met")
            print(f"✅ Ready for production use")
        else:
            print(f"\n⚠️  Integration completed with minor issues")
        
        return all_success, {
            'total_records': total_records,
            'date_rate': date_rate,
            'type_distribution': type_distribution.to_dict('records'),
            'date_range': date_range.to_dict()
        }
        
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False, {}

def generate_usage_examples():
    """Generate SQL query examples for using the corrected dataset"""
    examples_file = "database_usage_examples.sql"
    
    sql_examples = """
-- LexML Corrected Database - Usage Examples
-- Generated: {timestamp}

-- 1. Basic Statistics
SELECT 
    COUNT(*) as total_documents,
    COUNT(DISTINCT urn) as unique_documents,
    COUNT(CASE WHEN enacting_date IS NOT NULL THEN 1 END) as documents_with_dates
FROM lexml_documents_corrected;

-- 2. Document Type Distribution
SELECT 
    urn_type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents_corrected), 1) as percentage
FROM lexml_documents_corrected
GROUP BY urn_type
ORDER BY count DESC;

-- 3. Legislative Documents by Year
SELECT 
    substr(enacting_date, 1, 4) as year,
    COUNT(*) as legislation_count
FROM lexml_documents_corrected
WHERE urn_type = 'legislation' 
    AND enacting_date IS NOT NULL
GROUP BY substr(enacting_date, 1, 4)
ORDER BY year DESC;

-- 4. Most Productive Search Terms
SELECT 
    search_term,
    COUNT(*) as document_count,
    COUNT(CASE WHEN urn_type = 'legislation' THEN 1 END) as legislation_count
FROM lexml_documents_corrected
GROUP BY search_term
ORDER BY document_count DESC
LIMIT 20;

-- 5. Recent Legislative Activity (Last 5 Years)
SELECT 
    title,
    enacting_date,
    urn_type,
    search_term
FROM lexml_documents_corrected
WHERE urn_type = 'legislation'
    AND enacting_date >= '2019-01-01'
ORDER BY enacting_date DESC
LIMIT 50;

-- 6. Documents by Authority Type
SELECT 
    CASE 
        WHEN urn LIKE '%federal%' THEN 'Federal'
        WHEN urn LIKE '%estadual%' THEN 'State'
        WHEN urn LIKE '%municipal%' THEN 'Municipal'
        WHEN urn LIKE '%senado.federal%' THEN 'Senate'
        WHEN urn LIKE '%congresso.nacional%' THEN 'Congress'
        ELSE 'Other'
    END as authority_level,
    COUNT(*) as document_count
FROM lexml_documents_corrected
WHERE urn_type = 'legislation'
GROUP BY authority_level
ORDER BY document_count DESC;

-- 7. Transportation-Specific Legislation
SELECT 
    title,
    enacting_date,
    search_term
FROM lexml_documents_corrected
WHERE urn_type = 'legislation'
    AND (search_term LIKE '%transport%' 
         OR search_term LIKE '%caminhão%'
         OR search_term LIKE '%veículo%'
         OR search_term LIKE '%diesel%'
         OR search_term LIKE '%biodiesel%')
ORDER BY enacting_date DESC;

-- 8. Document Summary Analysis
SELECT 
    LENGTH(document_summary) as summary_length,
    COUNT(*) as count
FROM lexml_documents_corrected
WHERE document_summary IS NOT NULL
    AND document_summary != ''
GROUP BY LENGTH(document_summary) DIV 100 * 100
ORDER BY summary_length;

-- 9. Jurisprudence Analysis
SELECT 
    substr(enacting_date, 1, 4) as year,
    COUNT(*) as jurisprudence_count
FROM lexml_documents_corrected
WHERE urn_type = 'jurisprudence'
    AND enacting_date IS NOT NULL
GROUP BY substr(enacting_date, 1, 4)
ORDER BY year DESC;

-- 10. Data Quality Check
SELECT 
    'Total Records' as metric,
    COUNT(*) as value
FROM lexml_documents_corrected
UNION ALL
SELECT 
    'Records with Dates',
    COUNT(*)
FROM lexml_documents_corrected
WHERE enacting_date IS NOT NULL AND enacting_date != ''
UNION ALL
SELECT 
    'Records with Summaries',
    COUNT(*)
FROM lexml_documents_corrected
WHERE document_summary IS NOT NULL AND document_summary != ''
UNION ALL
SELECT 
    'Unique URNs',
    COUNT(DISTINCT urn)
FROM lexml_documents_corrected
WHERE urn IS NOT NULL;
""".format(timestamp=datetime.now().isoformat())
    
    with open(examples_file, 'w', encoding='utf-8') as f:
        f.write(sql_examples)
    
    print(f"📄 SQL usage examples saved: {examples_file}")
    return examples_file

def main():
    """Main verification function"""
    success, results = verify_database_integration()
    
    if success:
        examples_file = generate_usage_examples()
        print(f"\n📚 Additional Resources:")
        print(f"   SQL Examples: {examples_file}")
        print(f"   Database: ../data/processed/lexml_database.db")
        print(f"   Table: lexml_documents_corrected")
    
    return success

if __name__ == "__main__":
    main()