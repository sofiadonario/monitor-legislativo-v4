-- Add municipio column to existing documents table
-- This migration adds municipality support without dropping existing data

DO $$ 
BEGIN
    -- Add municipio column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='documents' AND column_name='municipio') THEN
        ALTER TABLE documents ADD COLUMN municipio VARCHAR(100);
        
        -- Create index for the new column
        CREATE INDEX idx_documents_municipio ON documents(municipio);
        
        -- Update existing records with sample municipality data
        UPDATE documents SET municipio = 'São Paulo' WHERE estado = 'SP';
        UPDATE documents SET municipio = 'Rio de Janeiro' WHERE estado = 'RJ';
        
        RAISE NOTICE 'Added municipio column and updated existing records';
    ELSE
        RAISE NOTICE 'municipio column already exists';
    END IF;
END $$;