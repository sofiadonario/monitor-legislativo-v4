-- Migration: Add document fingerprints table for deduplication service
-- This table stores document fingerprints for change detection and versioning

CREATE TABLE IF NOT EXISTS document_fingerprints (
    id SERIAL PRIMARY KEY,
    urn VARCHAR(500) NOT NULL UNIQUE,
    title_hash VARCHAR(64) NOT NULL,
    content_hash VARCHAR(64) NOT NULL, 
    metadata_hash VARCHAR(64) NOT NULL,
    full_hash VARCHAR(64) NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    word_count INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_document_fingerprints_urn ON document_fingerprints(urn);
CREATE INDEX IF NOT EXISTS idx_document_fingerprints_full_hash ON document_fingerprints(full_hash);
CREATE INDEX IF NOT EXISTS idx_document_fingerprints_last_seen ON document_fingerprints(last_seen);
CREATE INDEX IF NOT EXISTS idx_document_fingerprints_version ON document_fingerprints(version);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_document_fingerprints_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_document_fingerprints_updated_at
    BEFORE UPDATE ON document_fingerprints
    FOR EACH ROW
    EXECUTE FUNCTION update_document_fingerprints_updated_at();