-- Migration: Add export logs table and export configuration fields
-- This supports the automated export service functionality

-- Add export configuration fields to search_terms table
ALTER TABLE search_terms ADD COLUMN IF NOT EXISTS export_enabled BOOLEAN DEFAULT true;
ALTER TABLE search_terms ADD COLUMN IF NOT EXISTS last_export TIMESTAMP WITH TIME ZONE;

-- Create export logs table
CREATE TABLE IF NOT EXISTS export_logs (
    id SERIAL PRIMARY KEY,
    search_term_id INTEGER NOT NULL REFERENCES search_terms(id) ON DELETE CASCADE,
    export_format VARCHAR(20) NOT NULL,
    file_path TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    file_size_bytes BIGINT,
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for export logs
CREATE INDEX IF NOT EXISTS idx_export_logs_search_term_id ON export_logs(search_term_id);
CREATE INDEX IF NOT EXISTS idx_export_logs_created_at ON export_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_export_logs_format ON export_logs(export_format);
CREATE INDEX IF NOT EXISTS idx_export_logs_status ON export_logs(status);

-- Trigger to update updated_at timestamp on export_logs
CREATE OR REPLACE FUNCTION update_export_logs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_export_logs_updated_at
    BEFORE UPDATE ON export_logs
    FOR EACH ROW
    EXECUTE FUNCTION update_export_logs_updated_at();

-- Index for search_terms export fields
CREATE INDEX IF NOT EXISTS idx_search_terms_export_enabled ON search_terms(export_enabled);
CREATE INDEX IF NOT EXISTS idx_search_terms_last_export ON search_terms(last_export);