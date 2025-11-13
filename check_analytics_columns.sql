-- Check what columns are available for Analytics queries
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'documents'
  AND (column_name LIKE '%tipo%' OR column_name LIKE '%data%' OR column_name = 'date')
ORDER BY column_name;

-- Also check a sample row
SELECT urn, tipo, tipo_documento, data, date, ano, mes
FROM documents
LIMIT 5;
