-- Create indexes for performance optimization

-- Basic column indexes
CREATE INDEX IF NOT EXISTS idx_lexml_data ON lexml_documents(data);
CREATE INDEX IF NOT EXISTS idx_lexml_categoria ON lexml_documents(categoria);
CREATE INDEX IF NOT EXISTS idx_lexml_modal ON lexml_documents(modal);
CREATE INDEX IF NOT EXISTS idx_lexml_jurisdicao ON lexml_documents(jurisdicao);
CREATE INDEX IF NOT EXISTS idx_lexml_termo_busca ON lexml_documents(termo_busca);
CREATE INDEX IF NOT EXISTS idx_lexml_tipo ON lexml_documents(tipo);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_lexml_categoria_modal ON lexml_documents(categoria, modal);
CREATE INDEX IF NOT EXISTS idx_lexml_categoria_data ON lexml_documents(categoria, data);
CREATE INDEX IF NOT EXISTS idx_lexml_modal_data ON lexml_documents(modal, data);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_lexml_titulo_gin ON lexml_documents USING gin(to_tsvector('portuguese', titulo));
CREATE INDEX IF NOT EXISTS idx_lexml_ementa_gin ON lexml_documents USING gin(to_tsvector('portuguese', ementa));
CREATE INDEX IF NOT EXISTS idx_lexml_assuntos_gin ON lexml_documents USING gin(to_tsvector('portuguese', assuntos));

-- Performance statistics
ANALYZE lexml_documents;
ANALYZE categorias;
ANALYZE modais;
ANALYZE jurisdicoes;
ANALYZE termos_busca;