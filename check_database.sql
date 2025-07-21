
-- Simple SQL to check current database state
SELECT COUNT(*) as total_records FROM documents WHERE fonte = 'LexML';

-- Check for records with municipality-state issues
SELECT COUNT(*) as problematic_records 
FROM documents 
WHERE fonte = 'LexML' 
AND estado LIKE '%-%' 
AND estado NOT LIKE '%--%';

-- Sample problematic records
SELECT estado, municipality, titulo 
FROM documents 
WHERE fonte = 'LexML' 
AND estado LIKE '%-%'
LIMIT 5;
