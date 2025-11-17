-- Cleanup Script: Remove Non-Transportation Bills
-- Created: 2025-11-16
-- Purpose: Remove bills that are not related to transportation theme (Theme Code 61)
--
-- This script will:
-- 1. Identify bills in bill_events table that don't match transportation keywords
-- 2. Delete associated roll_call_votes
-- 3. Delete bill_events entries
--
-- Note: The 400-bill job currently running fetched bills WITHOUT theme filtering.
--       This script helps clean up those non-transportation bills.

BEGIN;

-- First, let's see what we're dealing with
SELECT
  'Bills to keep (Transportation-related)' as category,
  COUNT(DISTINCT bill_id) as count
FROM bill_events
WHERE
  LOWER(description) LIKE '%transporte%'
  OR LOWER(description) LIKE '%viação%'
  OR LOWER(description) LIKE '%mobilidade%'
  OR LOWER(description) LIKE '%trânsito%'
  OR LOWER(description) LIKE '%rodovia%'
  OR LOWER(description) LIKE '%ferrovia%'
  OR LOWER(description) LIKE '%metrô%'
  OR LOWER(description) LIKE '%ônibus%'
  OR LOWER(description) LIKE '%veículo%'

UNION ALL

SELECT
  'Bills to remove (Non-transportation)' as category,
  COUNT(DISTINCT bill_id) as count
FROM bill_events
WHERE
  bill_id NOT IN (
    SELECT DISTINCT bill_id
    FROM bill_events
    WHERE
      LOWER(description) LIKE '%transporte%'
      OR LOWER(description) LIKE '%viação%'
      OR LOWER(description) LIKE '%mobilidade%'
      OR LOWER(description) LIKE '%trânsito%'
      OR LOWER(description) LIKE '%rodovia%'
      OR LOWER(description) LIKE '%ferrovia%'
      OR LOWER(description) LIKE '%metrô%'
      OR LOWER(description) LIKE '%ônibus%'
      OR LOWER(description) LIKE '%veículo%'
  );

-- Create temporary table with bill_ids to remove
CREATE TEMPORARY TABLE bills_to_remove AS
SELECT DISTINCT bill_id
FROM bill_events
WHERE
  bill_id NOT IN (
    SELECT DISTINCT bill_id
    FROM bill_events
    WHERE
      LOWER(description) LIKE '%transporte%'
      OR LOWER(description) LIKE '%viação%'
      OR LOWER(description) LIKE '%mobilidade%'
      OR LOWER(description) LIKE '%trânsito%'
      OR LOWER(description) LIKE '%rodovia%'
      OR LOWER(description) LIKE '%ferrovia%'
      OR LOWER(description) LIKE '%metrô%'
      OR LOWER(description) LIKE '%ônibus%'
      OR LOWER(description) LIKE '%veículo%'
  );

-- Show sample of bills to be removed
SELECT
  'Sample bills to be removed:' as info,
  be.bill_id,
  LEFT(be.description, 100) as description_sample
FROM bill_events be
INNER JOIN bills_to_remove btr ON be.bill_id = btr.bill_id
LIMIT 10;

-- Delete roll_call_votes for non-transportation bills
DELETE FROM roll_call_votes
WHERE bill_id IN (SELECT bill_id FROM bills_to_remove);

-- Get count of deleted votes
SELECT 'Deleted roll_call_votes' as action, @@rowcount as count;

-- Delete bill_events for non-transportation bills
DELETE FROM bill_events
WHERE bill_id IN (SELECT bill_id FROM bills_to_remove);

-- Get count of deleted events
SELECT 'Deleted bill_events' as action, @@rowcount as count;

-- Show final counts
SELECT
  'Remaining Bills (Transportation-only)' as status,
  COUNT(DISTINCT bill_id) as bill_count,
  COUNT(*) as event_count
FROM bill_events;

-- Clean up temp table
DROP TABLE bills_to_remove;

-- COMMIT or ROLLBACK
-- Uncomment ONE of the following lines:
-- COMMIT;   -- Use this to save changes
ROLLBACK;   -- Use this to undo changes (safe default)

-- After reviewing the output above, if the cleanup looks correct:
-- 1. Comment out the ROLLBACK line
-- 2. Uncomment the COMMIT line
-- 3. Re-run the script
