-- Fix Database Data Structure Issues
-- Addresses the problems identified in the executive summary

-- ============================================================================
-- 1. FIX DOCUMENT CATEGORIES
-- ============================================================================

-- Fix categoria values to match expected strings
UPDATE documents 
SET categoria = 'Legislação'
WHERE categoria IN ('Legislacao', 'legislacao', 'LEGISLAÇÃO');

UPDATE documents 
SET categoria = 'Jurisprudência'
WHERE categoria IN ('Jurisprudencia', 'jurisprudencia', 'JURISPRUDÊNCIA');

UPDATE documents 
SET categoria = 'Doutrina'
WHERE categoria IN ('doutrina', 'DOUTRINA', 'library');

-- ============================================================================
-- 2. FIX FEDERAL DOCUMENTS
-- ============================================================================

-- Map "BR" to "DF" for Brasília (federal documents)
UPDATE documents 
SET estado = 'DF', municipality = 'Brasília'
WHERE estado = 'BR' AND (municipality IS NULL OR municipality = '');

-- ============================================================================
-- 3. EXTRACT STATE INFORMATION FROM URN FIELDS
-- ============================================================================

-- Extract state information from URN fields where possible
UPDATE documents 
SET estado = CASE 
  WHEN URN LIKE '%/sp/%' THEN 'SP'
  WHEN URN LIKE '%/rj/%' THEN 'RJ'
  WHEN URN LIKE '%/mg/%' THEN 'MG'
  WHEN URN LIKE '%/rs/%' THEN 'RS'
  WHEN URN LIKE '%/pr/%' THEN 'PR'
  WHEN URN LIKE '%/sc/%' THEN 'SC'
  WHEN URN LIKE '%/ba/%' THEN 'BA'
  WHEN URN LIKE '%/go/%' THEN 'GO'
  WHEN URN LIKE '%/pe/%' THEN 'PE'
  WHEN URN LIKE '%/ce/%' THEN 'CE'
  WHEN URN LIKE '%/pa/%' THEN 'PA'
  WHEN URN LIKE '%/ma/%' THEN 'MA'
  WHEN URN LIKE '%/pi/%' THEN 'PI'
  WHEN URN LIKE '%/rn/%' THEN 'RN'
  WHEN URN LIKE '%/se/%' THEN 'SE'
  WHEN URN LIKE '%/al/%' THEN 'AL'
  WHEN URN LIKE '%/pb/%' THEN 'PB'
  WHEN URN LIKE '%/es/%' THEN 'ES'
  WHEN URN LIKE '%/mt/%' THEN 'MT'
  WHEN URN LIKE '%/ms/%' THEN 'MS'
  WHEN URN LIKE '%/ro/%' THEN 'RO'
  WHEN URN LIKE '%/ac/%' THEN 'AC'
  WHEN URN LIKE '%/ap/%' THEN 'AP'
  WHEN URN LIKE '%/rr/%' THEN 'RR'
  WHEN URN LIKE '%/am/%' THEN 'AM'
  WHEN URN LIKE '%/to/%' THEN 'TO'
  ELSE estado
END
WHERE estado = 'BR' OR estado IS NULL;

-- ============================================================================
-- 4. CREATE BRAZILIAN STATES REFERENCE TABLE
-- ============================================================================

-- Create brazilian_states table if it doesn't exist
CREATE TABLE IF NOT EXISTS brazilian_states (
  abbrev VARCHAR(2) PRIMARY KEY,
  name VARCHAR(50) NOT NULL,
  region VARCHAR(20) NOT NULL,
  capital VARCHAR(50) NOT NULL,
  lat DECIMAL(10,8),
  lng DECIMAL(11,8)
);

-- Insert Brazilian states data
INSERT INTO brazilian_states (abbrev, name, region, capital, lat, lng) VALUES
('AC', 'Acre', 'Norte', 'Rio Branco', -8.77, -70.55),
('AL', 'Alagoas', 'Nordeste', 'Maceió', -9.71, -36.82),
('AP', 'Amapá', 'Norte', 'Macapá', 0.00, -51.77),
('AM', 'Amazonas', 'Norte', 'Manaus', -3.07, -65.74),
('BA', 'Bahia', 'Nordeste', 'Salvador', -12.96, -41.58),
('CE', 'Ceará', 'Nordeste', 'Fortaleza', -5.20, -39.73),
('DF', 'Distrito Federal', 'Centro-Oeste', 'Brasília', -15.83, -47.86),
('ES', 'Espírito Santo', 'Sudeste', 'Vitória', -19.19, -40.34),
('GO', 'Goiás', 'Centro-Oeste', 'Goiânia', -16.64, -49.31),
('MA', 'Maranhão', 'Nordeste', 'São Luís', -2.55, -45.28),
('MT', 'Mato Grosso', 'Centro-Oeste', 'Cuiabá', -15.60, -56.10),
('MS', 'Mato Grosso do Sul', 'Centro-Oeste', 'Campo Grande', -20.51, -54.54),
('MG', 'Minas Gerais', 'Sudeste', 'Belo Horizonte', -18.10, -45.00),
('PA', 'Pará', 'Norte', 'Belém', -5.53, -52.00),
('PB', 'Paraíba', 'Nordeste', 'João Pessoa', -7.06, -36.78),
('PR', 'Paraná', 'Sul', 'Curitiba', -24.89, -51.22),
('PE', 'Pernambuco', 'Nordeste', 'Recife', -8.28, -38.95),
('PI', 'Piauí', 'Nordeste', 'Teresina', -8.28, -43.68),
('RJ', 'Rio de Janeiro', 'Sudeste', 'Rio de Janeiro', -22.84, -43.68),
('RN', 'Rio Grande do Norte', 'Nordeste', 'Natal', -5.22, -36.95),
('RS', 'Rio Grande do Sul', 'Sul', 'Porto Alegre', -30.01, -52.09),
('RO', 'Rondônia', 'Norte', 'Porto Velho', -8.83, -62.76),
('RR', 'Roraima', 'Norte', 'Boa Vista', 2.73, -61.33),
('SC', 'Santa Catarina', 'Sul', 'Florianópolis', -27.33, -50.16),
('SP', 'São Paulo', 'Sudeste', 'São Paulo', -23.55, -48.64),
('SE', 'Sergipe', 'Nordeste', 'Aracaju', -10.90, -37.86),
('TO', 'Tocantins', 'Norte', 'Palmas', -10.25, -48.25)
ON CONFLICT (abbrev) DO NOTHING;

-- ============================================================================
-- 5. CREATE INDEXES FOR BETTER PERFORMANCE
-- ============================================================================

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado);
CREATE INDEX IF NOT EXISTS idx_documents_categoria ON documents(categoria);
CREATE INDEX IF NOT EXISTS idx_documents_municipality ON documents(municipality);
CREATE INDEX IF NOT EXISTS idx_documents_urn ON documents(urn);

-- ============================================================================
-- 6. VERIFICATION QUERIES
-- ============================================================================

-- Check the current state distribution
SELECT 
  estado, 
  COUNT(*) as count, 
  COUNT(DISTINCT municipality) as unique_municipalities
FROM documents 
WHERE estado IS NOT NULL 
GROUP BY estado 
ORDER BY count DESC 
LIMIT 10;

-- Check document categories
SELECT 
  categoria, 
  COUNT(*) as count
FROM documents 
WHERE categoria IS NOT NULL 
GROUP BY categoria 
ORDER BY count DESC;

-- Check municipality distribution
SELECT 
  municipality, 
  COUNT(*) as count
FROM documents 
WHERE municipality IS NOT NULL AND municipality != ''
GROUP BY municipality 
ORDER BY count DESC 
LIMIT 20;

-- ============================================================================
-- 7. CREATE VIEW FOR MAP DATA
-- ============================================================================

-- Create a view for easy map data access
CREATE OR REPLACE VIEW map_data AS
SELECT 
  bs.abbrev,
  bs.name,
  bs.region,
  bs.capital,
  bs.lat,
  bs.lng,
  COALESCE(doc_counts.total_docs, 0) as total_docs,
  COALESCE(doc_counts.legislacao, 0) as legislacao,
  COALESCE(doc_counts.jurisprudencia, 0) as jurisprudencia,
  COALESCE(doc_counts.doutrina, 0) as doutrina,
  COALESCE(doc_counts.outros, 0) as outros
FROM brazilian_states bs
LEFT JOIN (
  SELECT 
    estado as abbrev,
    COUNT(*) as total_docs,
    SUM(CASE WHEN categoria = 'Legislação' THEN 1 ELSE 0 END) as legislacao,
    SUM(CASE WHEN categoria = 'Jurisprudência' THEN 1 ELSE 0 END) as jurisprudencia,
    SUM(CASE WHEN categoria = 'Doutrina' THEN 1 ELSE 0 END) as doutrina,
    SUM(CASE WHEN categoria NOT IN ('Legislação', 'Jurisprudência', 'Doutrina') THEN 1 ELSE 0 END) as outros
  FROM documents 
  WHERE estado IS NOT NULL AND estado != ''
  GROUP BY estado
) doc_counts ON bs.abbrev = doc_counts.abbrev
WHERE COALESCE(doc_counts.total_docs, 0) > 0
ORDER BY total_docs DESC;

-- ============================================================================
-- 8. SUMMARY STATISTICS
-- ============================================================================

-- Get summary statistics after fixes
SELECT 
  'Total Documents' as metric,
  COUNT(*) as value
FROM documents
UNION ALL
SELECT 
  'States with Documents' as metric,
  COUNT(DISTINCT estado) as value
FROM documents
WHERE estado IS NOT NULL AND estado != ''
UNION ALL
SELECT 
  'Municipalities with Documents' as metric,
  COUNT(DISTINCT municipality) as value
FROM documents
WHERE municipality IS NOT NULL AND municipality != ''
UNION ALL
SELECT 
  'Document Categories' as metric,
  COUNT(DISTINCT categoria) as value
FROM documents
WHERE categoria IS NOT NULL AND categoria != ''; 