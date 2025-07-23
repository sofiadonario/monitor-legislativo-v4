-- Final verification of all imported tables

-- List all tables and their record counts
SELECT 
    'All Tables Summary' as section,
    schemaname,
    tablename,
    n_tup_ins as estimated_rows
FROM pg_stat_user_tables 
WHERE tablename LIKE 'lexml_%'
ORDER BY tablename;

-- Detailed verification by category
SELECT 'MAIN TABLE' as category, COUNT(*) as records FROM lexml_documents
UNION ALL
SELECT 'DOUTRINA TOTAL', SUM(cnt) FROM (
    SELECT COUNT(*) as cnt FROM lexml_doutrina_aereo
    UNION ALL SELECT COUNT(*) FROM lexml_doutrina_geral
    UNION ALL SELECT COUNT(*) FROM lexml_doutrina_maritimo
    UNION ALL SELECT COUNT(*) FROM lexml_doutrina_rodoviario
) t
UNION ALL
SELECT 'JURISPRUDENCIA TOTAL', SUM(cnt) FROM (
    SELECT COUNT(*) as cnt FROM lexml_jurisprudencia_aereo
    UNION ALL SELECT COUNT(*) FROM lexml_jurisprudencia_geral
    UNION ALL SELECT COUNT(*) FROM lexml_jurisprudencia_maritimo
    UNION ALL SELECT COUNT(*) FROM lexml_jurisprudencia_rodoviario
) t
UNION ALL
SELECT 'LEGISLACAO TOTAL', SUM(cnt) FROM (
    SELECT COUNT(*) as cnt FROM lexml_legislacao_aereo
    UNION ALL SELECT COUNT(*) FROM lexml_legislacao_geral
    UNION ALL SELECT COUNT(*) FROM lexml_legislacao_maritimo
    UNION ALL SELECT COUNT(*) FROM lexml_legislacao_rodoviario
) t
UNION ALL
SELECT 'OUTROS TOTAL', SUM(cnt) FROM (
    SELECT COUNT(*) as cnt FROM lexml_outros_aereo
    UNION ALL SELECT COUNT(*) FROM lexml_outros_geral
    UNION ALL SELECT COUNT(*) FROM lexml_outros_maritimo
    UNION ALL SELECT COUNT(*) FROM lexml_outros_rodoviario
) t
UNION ALL
SELECT 'PROPOSICOES TOTAL', SUM(cnt) FROM (
    SELECT COUNT(*) as cnt FROM lexml_proposicoes_aereo
    UNION ALL SELECT COUNT(*) FROM lexml_proposicoes_geral
    UNION ALL SELECT COUNT(*) FROM lexml_proposicoes_maritimo
    UNION ALL SELECT COUNT(*) FROM lexml_proposicoes_rodoviario
) t;

-- Index summary
SELECT 
    'Index Summary' as section,
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes 
WHERE tablename LIKE 'lexml_%'
AND indexname NOT LIKE '%_pkey'
ORDER BY tablename, indexname;

-- Database size information
SELECT 
    'Database Size' as section,
    pg_size_pretty(pg_total_relation_size('lexml_documents')) as main_table_size,
    pg_size_pretty(sum(pg_total_relation_size(quote_ident(tablename)))) as all_tables_size
FROM information_schema.tables 
WHERE table_name LIKE 'lexml_%'
AND table_schema = 'public';

-- Sample data quality check
SELECT 
    'Data Quality Check' as section,
    'Records with valid dates' as metric,
    COUNT(CASE WHEN data IS NOT NULL THEN 1 END) as count
FROM lexml_documents
UNION ALL
SELECT 
    'Data Quality Check',
    'Records with ementa',
    COUNT(CASE WHEN ementa IS NOT NULL AND ementa != '' THEN 1 END)
FROM lexml_documents;