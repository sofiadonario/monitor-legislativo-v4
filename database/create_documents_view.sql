-- Create a view to match the R Shiny app's expected column names
-- The app expects: id, titulo, tipo, data, origem
-- The table has: id, titulo, tipo, data_publicacao, fonte

-- Option 1: Create a view (recommended - no schema change needed)
DROP VIEW IF EXISTS documents_view CASCADE;

CREATE VIEW documents_view AS
SELECT
    id,
    titulo,
    tipo,
    data_publicacao AS data,
    fonte AS origem,
    url,
    estado,
    autor,
    conteudo,
    metadata,
    transport_category,
    created_at,
    updated_at
FROM documents;

-- Grant permissions
GRANT SELECT ON documents_view TO monitor_user;

-- Test the view
SELECT id, titulo, tipo, data, origem
FROM documents_view
LIMIT 5;
