-- Check counts for all lexml tables
SELECT table_name, 
       (xpath('/row/count/text()', 
              query_to_xml(format('SELECT COUNT(*) AS count FROM %I', table_name), 
                           false, true, '')))[1]::text::int AS row_count
FROM information_schema.tables
WHERE table_schema = 'public' 
  AND table_name LIKE 'lexml_%'
  AND table_name NOT IN ('lexml_documents', 'lexml_parsed_enhanced_fixed')
ORDER BY table_name;