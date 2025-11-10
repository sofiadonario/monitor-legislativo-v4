-- Check column population rates for indexed columns
SELECT
    'titulo' as column_name,
    COUNT(*) as total_rows,
    COUNT(titulo) as non_null_rows,
    COUNT(CASE WHEN titulo != '' THEN 1 END) as non_empty_rows,
    ROUND(100.0 * COUNT(titulo) / COUNT(*), 2) as pct_non_null,
    ROUND(100.0 * COUNT(CASE WHEN titulo != '' THEN 1 END) / COUNT(*), 2) as pct_non_empty
FROM documents
UNION ALL
SELECT
    'ementa',
    COUNT(*),
    COUNT(ementa),
    COUNT(CASE WHEN ementa != '' THEN 1 END),
    ROUND(100.0 * COUNT(ementa) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN ementa != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'autor',
    COUNT(*),
    COUNT(autor),
    COUNT(CASE WHEN autor != '' THEN 1 END),
    ROUND(100.0 * COUNT(autor) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN autor != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'estado',
    COUNT(*),
    COUNT(estado),
    COUNT(CASE WHEN estado != '' THEN 1 END),
    ROUND(100.0 * COUNT(estado) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN estado != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'municipio',
    COUNT(*),
    COUNT(municipio),
    COUNT(CASE WHEN municipio != '' THEN 1 END),
    ROUND(100.0 * COUNT(municipio) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN municipio != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'data',
    COUNT(*),
    COUNT(data),
    COUNT(CASE WHEN data != '' THEN 1 END),
    ROUND(100.0 * COUNT(data) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN data != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'ano',
    COUNT(*),
    COUNT(ano),
    COUNT(CASE WHEN ano != '' THEN 1 END),
    ROUND(100.0 * COUNT(ano) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN ano != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'tipo',
    COUNT(*),
    COUNT(tipo),
    COUNT(CASE WHEN tipo != '' THEN 1 END),
    ROUND(100.0 * COUNT(tipo) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN tipo != '' THEN 1 END) / COUNT(*), 2)
FROM documents
UNION ALL
SELECT
    'urn',
    COUNT(*),
    COUNT(urn),
    COUNT(CASE WHEN urn != '' THEN 1 END),
    ROUND(100.0 * COUNT(urn) / COUNT(*), 2),
    ROUND(100.0 * COUNT(CASE WHEN urn != '' THEN 1 END) / COUNT(*), 2)
FROM documents
ORDER BY column_name;
