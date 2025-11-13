-- Check which date and type columns exist in documents table
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name='documents'
  AND (column_name LIKE '%data%' OR column_name LIKE '%tipo%' OR column_name = 'date')
ORDER BY column_name;
