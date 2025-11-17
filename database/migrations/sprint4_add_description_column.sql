-- Sprint 4: Add description column to bill_events table
-- This adds the missing description field that the API populates
-- Created: 2025-11-16

-- Add description column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'bill_events' AND column_name = 'description'
    ) THEN
        ALTER TABLE bill_events ADD COLUMN description TEXT;
        RAISE NOTICE 'Added description column to bill_events table';
    ELSE
        RAISE NOTICE 'description column already exists in bill_events table';
    END IF;
END $$;
