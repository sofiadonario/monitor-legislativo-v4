-- Add location columns to all lexml database tables
-- This will support proper location parsing and municipality data

-- Add columns to lexml_documents (main table)
ALTER TABLE lexml_documents 
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_legislacao_geral
ALTER TABLE lexml_legislacao_geral
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_legislacao_aereo
ALTER TABLE lexml_legislacao_aereo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_legislacao_maritimo
ALTER TABLE lexml_legislacao_maritimo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_legislacao_rodoviario
ALTER TABLE lexml_legislacao_rodoviario
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_jurisprudencia_geral
ALTER TABLE lexml_jurisprudencia_geral
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_jurisprudencia_aereo
ALTER TABLE lexml_jurisprudencia_aereo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_jurisprudencia_maritimo
ALTER TABLE lexml_jurisprudencia_maritimo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_jurisprudencia_rodoviario
ALTER TABLE lexml_jurisprudencia_rodoviario
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_doutrina_geral
ALTER TABLE lexml_doutrina_geral
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_doutrina_aereo
ALTER TABLE lexml_doutrina_aereo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_doutrina_maritimo
ALTER TABLE lexml_doutrina_maritimo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_doutrina_rodoviario
ALTER TABLE lexml_doutrina_rodoviario
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_outros_geral
ALTER TABLE lexml_outros_geral
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_outros_aereo
ALTER TABLE lexml_outros_aereo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_outros_maritimo
ALTER TABLE lexml_outros_maritimo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_outros_rodoviario
ALTER TABLE lexml_outros_rodoviario
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_proposicoes_geral
ALTER TABLE lexml_proposicoes_geral
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_proposicoes_aereo
ALTER TABLE lexml_proposicoes_aereo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_proposicoes_maritimo
ALTER TABLE lexml_proposicoes_maritimo
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Add columns to lexml_proposicoes_rodoviario
ALTER TABLE lexml_proposicoes_rodoviario
ADD COLUMN IF NOT EXISTS pais VARCHAR(50),
ADD COLUMN IF NOT EXISTS estado_sigla VARCHAR(2),
ADD COLUMN IF NOT EXISTS municipio VARCHAR(255);

-- Update default values for all tables (Brazil as default country)
UPDATE lexml_documents SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_legislacao_geral SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_legislacao_aereo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_legislacao_maritimo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_legislacao_rodoviario SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_jurisprudencia_geral SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_jurisprudencia_aereo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_jurisprudencia_maritimo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_jurisprudencia_rodoviario SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_doutrina_geral SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_doutrina_aereo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_doutrina_maritimo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_doutrina_rodoviario SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_outros_geral SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_outros_aereo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_outros_maritimo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_outros_rodoviario SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_proposicoes_geral SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_proposicoes_aereo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_proposicoes_maritimo SET pais = 'Brasil' WHERE pais IS NULL;
UPDATE lexml_proposicoes_rodoviario SET pais = 'Brasil' WHERE pais IS NULL;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_lexml_documents_estado_sigla ON lexml_documents(estado_sigla);
CREATE INDEX IF NOT EXISTS idx_lexml_documents_municipio ON lexml_documents(municipio);

-- Verify the schema changes
SELECT 'Location columns added successfully to all tables' as status;
SELECT table_name, column_name 
FROM information_schema.columns 
WHERE column_name IN ('pais', 'estado_sigla', 'municipio') 
  AND table_name LIKE 'lexml_%'
ORDER BY table_name, column_name;