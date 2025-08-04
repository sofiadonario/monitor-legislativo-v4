-- CREATE DASHBOARD VIEWS AND COMPLETE DATABASE SETUP
-- This script creates all necessary views for the dashboard

-- Main dashboard summary view
CREATE OR REPLACE VIEW lexml_dashboard_view AS
SELECT 
    d.id,
    d.titulo,
    d.urn,
    d.url,
    d.ementa,
    d.data,
    d.ano,
    d.estado,
    d.municipio,
    dc.name as categoria,
    tm.name as modal,
    j.name as jurisdicao,
    d.extracted_category,
    d.extracted_transport_mode,
    d.deduplication_source,
    d.original_count
FROM documents d
LEFT JOIN document_categories dc ON d.category_id = dc.id
LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
LEFT JOIN jurisdictions j ON d.jurisdiction_id = j.id;

-- Documents by category view
CREATE OR REPLACE VIEW documents_by_category AS
SELECT 
    dc.name as categoria,
    dc.description,
    COUNT(*) as total_documents,
    COUNT(DISTINCT d.estado) as states_covered,
    MIN(d.ano) as earliest_year,
    MAX(d.ano) as latest_year,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
FROM documents d
LEFT JOIN document_categories dc ON d.category_id = dc.id
WHERE dc.name IS NOT NULL
GROUP BY dc.id, dc.name, dc.description
ORDER BY total_documents DESC;

-- Documents by state view
CREATE OR REPLACE VIEW documents_by_state AS
SELECT 
    d.estado,
    COUNT(*) as total_documents,
    COUNT(DISTINCT dc.name) as categories_covered,
    COUNT(DISTINCT tm.name) as transport_modes_covered,
    MIN(d.ano) as earliest_year,
    MAX(d.ano) as latest_year
FROM documents d
LEFT JOIN document_categories dc ON d.category_id = dc.id
LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
WHERE d.estado IS NOT NULL AND d.estado != ''
GROUP BY d.estado
ORDER BY total_documents DESC;

-- Documents by transport mode view
CREATE OR REPLACE VIEW documents_by_transport AS
SELECT 
    tm.name as modal,
    tm.description,
    COUNT(*) as total_documents,
    COUNT(DISTINCT d.estado) as states_covered,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
FROM documents d
LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
WHERE tm.name IS NOT NULL
GROUP BY tm.id, tm.name, tm.description
ORDER BY total_documents DESC;

-- Dashboard metrics view
CREATE OR REPLACE VIEW dashboard_metrics AS
SELECT 
    (SELECT COUNT(*) FROM documents) as total_documents,
    (SELECT COUNT(DISTINCT estado) FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado != 'Federal') as states_with_documents,
    (SELECT COUNT(DISTINCT category_id) FROM documents WHERE category_id IS NOT NULL) as total_categories,
    (SELECT COUNT(DISTINCT transport_mode_id) FROM documents WHERE transport_mode_id IS NOT NULL) as total_transport_modes,
    (SELECT MIN(ano) FROM documents WHERE ano IS NOT NULL) as earliest_year,
    (SELECT MAX(ano) FROM documents WHERE ano IS NOT NULL) as latest_year,
    CURRENT_TIMESTAMP as last_updated;

-- Helper function to get documents by category
CREATE OR REPLACE FUNCTION get_documents_by_category(category_name TEXT DEFAULT NULL, limit_rows INTEGER DEFAULT 100)
RETURNS TABLE(
    id INTEGER,
    titulo TEXT,
    categoria TEXT,
    estado TEXT,
    ano INTEGER,
    total_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.id,
        d.titulo,
        dc.name as categoria,
        d.estado,
        d.ano,
        COUNT(*) OVER() as total_count
    FROM documents d
    LEFT JOIN document_categories dc ON d.category_id = dc.id
    WHERE (category_name IS NULL OR dc.name = category_name)
    ORDER BY d.id
    LIMIT limit_rows;
END;
$$ LANGUAGE plpgsql;

-- Helper function to get documents by state
CREATE OR REPLACE FUNCTION get_documents_by_state_func(state_name TEXT DEFAULT NULL, limit_rows INTEGER DEFAULT 100)
RETURNS TABLE(
    id INTEGER,
    titulo TEXT,
    categoria TEXT,
    estado TEXT,
    ano INTEGER,
    total_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.id,
        d.titulo,
        dc.name as categoria,
        d.estado,
        d.ano,
        COUNT(*) OVER() as total_count
    FROM documents d
    LEFT JOIN document_categories dc ON d.category_id = dc.id
    WHERE (state_name IS NULL OR d.estado = state_name)
    ORDER BY d.id
    LIMIT limit_rows;
END;
$$ LANGUAGE plpgsql;

-- Summary statistics view for quick dashboard loading
CREATE OR REPLACE VIEW dashboard_summary AS
SELECT 
    'total_documents' as metric,
    (SELECT COUNT(*)::TEXT FROM documents) as value,
    'Total documents in database' as description
UNION ALL
SELECT 
    'categories',
    (SELECT COUNT(DISTINCT category_id)::TEXT FROM documents WHERE category_id IS NOT NULL),
    'Distinct categories available'
UNION ALL
SELECT 
    'states_with_docs',
    (SELECT COUNT(DISTINCT estado)::TEXT FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado != 'Federal'),
    'States with documents (excluding Federal)'
UNION ALL
SELECT 
    'jurisprudencia_docs',
    (SELECT COUNT(*)::TEXT FROM documents d JOIN document_categories dc ON d.category_id = dc.id WHERE dc.name = 'Jurisprudência'),
    'Jurisprudência documents'
UNION ALL
SELECT 
    'legislacao_docs',
    (SELECT COUNT(*)::TEXT FROM documents d JOIN document_categories dc ON d.category_id = dc.id WHERE dc.name = 'Legislação'),
    'Legislação documents'
UNION ALL
SELECT 
    'date_range',
    (SELECT CONCAT(MIN(ano), '-', MAX(ano)) FROM documents WHERE ano IS NOT NULL),
    'Year range of documents';

SELECT 'Dashboard views created successfully!' as status;