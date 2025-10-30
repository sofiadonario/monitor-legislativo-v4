-- ============================================================================
-- Add ID Column to Documents Table
-- ============================================================================
-- Run this in Google Cloud Console Query Editor:
-- https://console.cloud.google.com/sql/instances/mackmonitor-db/query?project=mackmonitor
-- ============================================================================

-- Add the id column as a SERIAL PRIMARY KEY
-- This will automatically create a sequence and populate existing rows with unique IDs
ALTER TABLE documents ADD COLUMN id SERIAL PRIMARY KEY;

-- Verify the column was added
\d documents

-- Show first 10 rows with the new id column
SELECT id, titulo, tipo, data, origem
FROM documents
ORDER BY id
LIMIT 10;

-- Show total count
SELECT COUNT(*) as total_documents FROM documents;
