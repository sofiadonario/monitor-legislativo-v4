-- =============================================================================
-- Sprint 3: Advanced NLP Schema Migration
-- =============================================================================
-- Description: Creates database tables for Word2Vec, GloVe, BERT embeddings,
--              Structural Topic Models (STM), and semantic similarity caching
-- Version: 1.0
-- Date: January 2025
-- Run before: Starting Sprint 3 implementation
-- =============================================================================

BEGIN;

-- Log migration start
DO $$
BEGIN
  RAISE NOTICE 'Starting Sprint 3 NLP schema migration...';
END $$;

-- =============================================================================
-- PART 1: Word Embeddings (Word2Vec & GloVe)
-- =============================================================================

-- Table: document_embeddings
-- Purpose: Store 300-dimensional document embeddings (avg of word vectors)
CREATE TABLE IF NOT EXISTS document_embeddings (
  id SERIAL PRIMARY KEY,
  document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
  embedding_type TEXT NOT NULL CHECK (embedding_type IN ('word2vec', 'glove', 'bert')),
  embedding FLOAT8[] NOT NULL,
  embedding_version TEXT DEFAULT '1.0',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(document_id, embedding_type)
);

CREATE INDEX IF NOT EXISTS idx_document_embeddings_doc_id
  ON document_embeddings(document_id);
CREATE INDEX IF NOT EXISTS idx_document_embeddings_type
  ON document_embeddings(embedding_type);
CREATE INDEX IF NOT EXISTS idx_document_embeddings_created
  ON document_embeddings(created_at DESC);

COMMENT ON TABLE document_embeddings IS
  'Document-level embeddings from Word2Vec, GloVe, or BERT models';
COMMENT ON COLUMN document_embeddings.embedding IS
  '300-dim for Word2Vec/GloVe, 768-dim for BERT';

-- Table: word_embeddings
-- Purpose: Store word-level embeddings vocabulary (for semantic word search)
CREATE TABLE IF NOT EXISTS word_embeddings (
  id SERIAL PRIMARY KEY,
  word TEXT NOT NULL,
  embedding_type TEXT NOT NULL CHECK (embedding_type IN ('word2vec', 'glove')),
  embedding FLOAT8[] NOT NULL,
  frequency INTEGER DEFAULT 0,
  model_version TEXT DEFAULT '1.0',
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(word, embedding_type)
);

CREATE INDEX IF NOT EXISTS idx_word_embeddings_word
  ON word_embeddings(word);
CREATE INDEX IF NOT EXISTS idx_word_embeddings_type
  ON word_embeddings(embedding_type);
CREATE INDEX IF NOT EXISTS idx_word_embeddings_freq
  ON word_embeddings(frequency DESC);

COMMENT ON TABLE word_embeddings IS
  'Word-level vocabulary embeddings for semantic word similarity search';

-- =============================================================================
-- PART 2: Semantic Similarity Cache
-- =============================================================================

-- Table: semantic_similarity_cache
-- Purpose: Pre-computed similarity scores between document pairs (top-10 per doc)
CREATE TABLE IF NOT EXISTS semantic_similarity_cache (
  id SERIAL PRIMARY KEY,
  doc1_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
  doc2_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
  similarity_score FLOAT8 NOT NULL CHECK (similarity_score >= 0 AND similarity_score <= 1),
  embedding_type TEXT NOT NULL,
  rank_position INTEGER,  -- 1st, 2nd, 3rd most similar
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(doc1_id, doc2_id, embedding_type)
);

CREATE INDEX IF NOT EXISTS idx_semantic_similarity_doc1
  ON semantic_similarity_cache(doc1_id, similarity_score DESC);
CREATE INDEX IF NOT EXISTS idx_semantic_similarity_doc2
  ON semantic_similarity_cache(doc2_id);
CREATE INDEX IF NOT EXISTS idx_semantic_similarity_score
  ON semantic_similarity_cache(similarity_score DESC);
CREATE INDEX IF NOT EXISTS idx_semantic_similarity_type
  ON semantic_similarity_cache(embedding_type);

COMMENT ON TABLE semantic_similarity_cache IS
  'Pre-computed top-10 similar documents per document for fast retrieval';

-- =============================================================================
-- PART 3: Structural Topic Models (STM)
-- =============================================================================

-- Table: stm_models
-- Purpose: Metadata for trained STM models
CREATE TABLE IF NOT EXISTS stm_models (
  id SERIAL PRIMARY KEY,
  model_name TEXT NOT NULL UNIQUE,
  num_topics INTEGER NOT NULL CHECK (num_topics >= 5 AND num_topics <= 100),
  model_version TEXT DEFAULT '1.0',
  prevalence_formula TEXT,  -- e.g., "~ nivel + poder + s(ano)"
  content_formula TEXT,      -- e.g., "~ nivel"
  trained_at TIMESTAMP DEFAULT NOW(),
  model_path TEXT,           -- GCS path: gs://mackmonitor/models/stm_k30.rds

  -- Model quality metrics
  semantic_coherence FLOAT8,
  exclusivity FLOAT8,
  heldout_likelihood FLOAT8,

  -- Training metadata
  num_documents INTEGER,
  vocabulary_size INTEGER,
  convergence_iterations INTEGER,

  is_active BOOLEAN DEFAULT TRUE  -- Only one active model at a time
);

CREATE INDEX IF NOT EXISTS idx_stm_models_active
  ON stm_models(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_stm_models_trained
  ON stm_models(trained_at DESC);

COMMENT ON TABLE stm_models IS
  'Metadata for Structural Topic Models with covariate effects';

-- Table: stm_topics
-- Purpose: Topic definitions (top words, labels)
CREATE TABLE IF NOT EXISTS stm_topics (
  id SERIAL PRIMARY KEY,
  model_id INTEGER REFERENCES stm_models(id) ON DELETE CASCADE,
  topic_number INTEGER NOT NULL CHECK (topic_number >= 1),
  topic_label TEXT,          -- Human-assigned label (e.g., "Health Policy")
  topic_label_auto TEXT,     -- Auto-generated from top words
  top_words TEXT[] NOT NULL, -- Top 10-20 words
  top_words_frex TEXT[],     -- FREX words (frequency-exclusivity)
  expected_proportion FLOAT8 CHECK (expected_proportion >= 0 AND expected_proportion <= 1),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(model_id, topic_number)
);

CREATE INDEX IF NOT EXISTS idx_stm_topics_model
  ON stm_topics(model_id);
CREATE INDEX IF NOT EXISTS idx_stm_topics_number
  ON stm_topics(topic_number);
CREATE INDEX IF NOT EXISTS idx_stm_topics_proportion
  ON stm_topics(expected_proportion DESC);

COMMENT ON TABLE stm_topics IS
  'Topic definitions with top words and labels for each STM model';

-- Table: document_topics
-- Purpose: Document-topic proportions (theta matrix)
CREATE TABLE IF NOT EXISTS document_topics (
  id SERIAL PRIMARY KEY,
  document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
  model_id INTEGER REFERENCES stm_models(id) ON DELETE CASCADE,
  topic_number INTEGER NOT NULL,
  proportion FLOAT8 NOT NULL CHECK (proportion >= 0 AND proportion <= 1),
  rank_position INTEGER,  -- 1st, 2nd, 3rd dominant topic
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(document_id, model_id, topic_number)
);

CREATE INDEX IF NOT EXISTS idx_document_topics_doc
  ON document_topics(document_id);
CREATE INDEX IF NOT EXISTS idx_document_topics_model
  ON document_topics(model_id);
CREATE INDEX IF NOT EXISTS idx_document_topics_topic
  ON document_topics(topic_number);
CREATE INDEX IF NOT EXISTS idx_document_topics_proportion
  ON document_topics(proportion DESC);

COMMENT ON TABLE document_topics IS
  'Document-topic proportions (theta) from STM models';

-- Table: stm_effects
-- Purpose: Covariate effects on topic prevalence
CREATE TABLE IF NOT EXISTS stm_effects (
  id SERIAL PRIMARY KEY,
  model_id INTEGER REFERENCES stm_models(id) ON DELETE CASCADE,
  topic_number INTEGER NOT NULL,
  covariate TEXT NOT NULL,   -- e.g., "nivel", "poder", "ano"
  covariate_value TEXT,       -- e.g., "Federal", "Estadual"
  effect_estimate FLOAT8 NOT NULL,
  standard_error FLOAT8,
  lower_ci FLOAT8,
  upper_ci FLOAT8,
  t_statistic FLOAT8,
  p_value FLOAT8,
  is_significant BOOLEAN GENERATED ALWAYS AS (p_value < 0.05) STORED,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stm_effects_model
  ON stm_effects(model_id);
CREATE INDEX IF NOT EXISTS idx_stm_effects_topic
  ON stm_effects(topic_number);
CREATE INDEX IF NOT EXISTS idx_stm_effects_covariate
  ON stm_effects(covariate);
CREATE INDEX IF NOT EXISTS idx_stm_effects_significant
  ON stm_effects(is_significant) WHERE is_significant = TRUE;

COMMENT ON TABLE stm_effects IS
  'Statistical effects of covariates (jurisdiction, time) on topic prevalence';

-- =============================================================================
-- PART 4: BERT Embeddings (768-dimensional)
-- =============================================================================

-- Table: bert_embeddings
-- Purpose: Store 768-dim contextualized BERT embeddings
-- Note: Stored separately from document_embeddings due to larger dimensionality
CREATE TABLE IF NOT EXISTS bert_embeddings (
  id SERIAL PRIMARY KEY,
  document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE UNIQUE,
  embedding FLOAT8[] NOT NULL,
  model_name TEXT DEFAULT 'neuralmind/bert-base-portuguese-cased',
  embedding_version TEXT DEFAULT '1.0',
  chunk_number INTEGER DEFAULT 1,  -- For long documents split into chunks
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bert_embeddings_doc
  ON bert_embeddings(document_id);
CREATE INDEX IF NOT EXISTS idx_bert_embeddings_model
  ON bert_embeddings(model_name);
CREATE INDEX IF NOT EXISTS idx_bert_embeddings_created
  ON bert_embeddings(created_at DESC);

COMMENT ON TABLE bert_embeddings IS
  'BERT contextualized embeddings (768-dim) for semantic similarity';

-- =============================================================================
-- PART 5: Materialized Views for Fast Queries
-- =============================================================================

-- Materialized View: top_similar_documents
-- Purpose: Pre-computed top 10 similar documents per document (Word2Vec)
CREATE MATERIALIZED VIEW IF NOT EXISTS top_similar_documents AS
SELECT DISTINCT ON (ssc.doc1_id, ssc.rank_position)
  ssc.doc1_id,
  ssc.doc2_id,
  ssc.similarity_score,
  ssc.rank_position,
  d2.titulo AS similar_doc_title,
  d2.tipo_documento AS similar_doc_type,
  d2.nivel AS similar_jurisdiction,
  d2.data_publicacao AS similar_pub_date
FROM semantic_similarity_cache ssc
JOIN documents d2 ON ssc.doc2_id = d2.id
WHERE ssc.embedding_type = 'word2vec'
  AND ssc.rank_position <= 10
ORDER BY ssc.doc1_id, ssc.rank_position, ssc.similarity_score DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_top_similar_docs_unique
  ON top_similar_documents(doc1_id, rank_position);
CREATE INDEX IF NOT EXISTS idx_top_similar_docs_doc1
  ON top_similar_documents(doc1_id);

COMMENT ON MATERIALIZED VIEW top_similar_documents IS
  'Fast lookup: Top 10 similar documents per document (Word2Vec)';

-- Materialized View: dominant_topics
-- Purpose: Primary topic for each document
CREATE MATERIALIZED VIEW IF NOT EXISTS dominant_topics AS
SELECT DISTINCT ON (dt.document_id)
  dt.document_id,
  dt.topic_number,
  st.topic_label,
  st.topic_label_auto,
  st.top_words,
  dt.proportion AS topic_proportion,
  d.titulo,
  d.tipo_documento,
  d.nivel,
  d.data_publicacao
FROM document_topics dt
JOIN stm_topics st ON dt.model_id = st.model_id AND dt.topic_number = st.topic_number
JOIN documents d ON dt.document_id = d.id
JOIN stm_models sm ON dt.model_id = sm.id
WHERE sm.is_active = TRUE
ORDER BY dt.document_id, dt.proportion DESC;

CREATE UNIQUE INDEX IF NOT EXISTS idx_dominant_topics_doc
  ON dominant_topics(document_id);
CREATE INDEX IF NOT EXISTS idx_dominant_topics_topic
  ON dominant_topics(topic_number);

COMMENT ON MATERIALIZED VIEW dominant_topics IS
  'Primary topic assignment for each document from active STM model';

-- Materialized View: topic_summary
-- Purpose: Topic statistics and top documents
CREATE MATERIALIZED VIEW IF NOT EXISTS topic_summary AS
SELECT
  st.model_id,
  st.topic_number,
  st.topic_label,
  st.topic_label_auto,
  st.top_words,
  st.expected_proportion,
  COUNT(DISTINCT dt.document_id) AS num_documents,
  AVG(dt.proportion) AS avg_proportion,

  -- Top 5 documents for this topic
  ARRAY_AGG(DISTINCT d.titulo ORDER BY dt.proportion DESC)
    FILTER (WHERE dt.rank_position <= 5) AS top_documents
FROM stm_topics st
JOIN document_topics dt ON st.model_id = dt.model_id AND st.topic_number = dt.topic_number
JOIN documents d ON dt.document_id = d.id
JOIN stm_models sm ON st.model_id = sm.id
WHERE sm.is_active = TRUE
GROUP BY st.model_id, st.topic_number, st.topic_label, st.topic_label_auto,
         st.top_words, st.expected_proportion;

CREATE UNIQUE INDEX IF NOT EXISTS idx_topic_summary_unique
  ON topic_summary(model_id, topic_number);

COMMENT ON MATERIALIZED VIEW topic_summary IS
  'Aggregate statistics and top documents per topic';

-- =============================================================================
-- PART 6: Helper Functions
-- =============================================================================

-- Function: refresh_nlp_views
-- Purpose: Refresh all NLP-related materialized views
CREATE OR REPLACE FUNCTION refresh_nlp_views()
RETURNS TEXT AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY top_similar_documents;
  REFRESH MATERIALIZED VIEW CONCURRENTLY dominant_topics;
  REFRESH MATERIALIZED VIEW CONCURRENTLY topic_summary;

  RETURN 'Successfully refreshed 3 NLP materialized views';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_nlp_views() IS
  'Refresh all NLP materialized views after batch jobs complete';

-- Function: get_similar_documents
-- Purpose: Fast retrieval of similar documents
CREATE OR REPLACE FUNCTION get_similar_documents(
  p_document_id INTEGER,
  p_limit INTEGER DEFAULT 10
)
RETURNS TABLE (
  similar_doc_id INTEGER,
  similarity_score FLOAT8,
  titulo TEXT,
  tipo_documento TEXT,
  nivel TEXT,
  data_publicacao DATE
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    tsd.doc2_id,
    tsd.similarity_score,
    tsd.similar_doc_title,
    tsd.similar_doc_type,
    tsd.similar_jurisdiction,
    tsd.similar_pub_date
  FROM top_similar_documents tsd
  WHERE tsd.doc1_id = p_document_id
  ORDER BY tsd.rank_position
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_similar_documents(INTEGER, INTEGER) IS
  'Retrieve top N similar documents for a given document ID';

-- Function: get_document_topics
-- Purpose: Get top topics for a document
CREATE OR REPLACE FUNCTION get_document_topics(
  p_document_id INTEGER,
  p_limit INTEGER DEFAULT 5
)
RETURNS TABLE (
  topic_number INTEGER,
  topic_label TEXT,
  top_words TEXT[],
  proportion FLOAT8
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    dt.topic_number,
    st.topic_label,
    st.top_words,
    dt.proportion
  FROM document_topics dt
  JOIN stm_topics st ON dt.model_id = st.model_id AND dt.topic_number = st.topic_number
  JOIN stm_models sm ON dt.model_id = sm.id
  WHERE dt.document_id = p_document_id
    AND sm.is_active = TRUE
  ORDER BY dt.proportion DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_document_topics(INTEGER, INTEGER) IS
  'Retrieve top N topics for a given document';

-- =============================================================================
-- PART 7: Triggers for Auto-Update
-- =============================================================================

-- Trigger: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_document_embeddings_timestamp
  BEFORE UPDATE ON document_embeddings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bert_embeddings_timestamp
  BEFORE UPDATE ON bert_embeddings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_stm_topics_timestamp
  BEFORE UPDATE ON stm_topics
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- PART 8: Grants and Permissions
-- =============================================================================

-- Grant permissions to application user (assuming 'mackmonitor_app')
-- Adjust username if different
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mackmonitor_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mackmonitor_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mackmonitor_app;
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mackmonitor_app;
  END IF;
END $$;

-- =============================================================================
-- PART 9: Verification and Summary
-- =============================================================================

COMMIT;

-- Verification queries
DO $$
DECLARE
  table_count INTEGER;
  view_count INTEGER;
  function_count INTEGER;
BEGIN
  -- Count new tables
  SELECT COUNT(*) INTO table_count
  FROM information_schema.tables
  WHERE table_schema = 'public'
    AND table_name IN (
      'document_embeddings', 'word_embeddings', 'semantic_similarity_cache',
      'stm_models', 'stm_topics', 'document_topics', 'stm_effects',
      'bert_embeddings'
    );

  -- Count new materialized views
  SELECT COUNT(*) INTO view_count
  FROM pg_matviews
  WHERE schemaname = 'public'
    AND matviewname IN (
      'top_similar_documents', 'dominant_topics', 'topic_summary'
    );

  -- Count new functions
  SELECT COUNT(*) INTO function_count
  FROM pg_proc p
  JOIN pg_namespace n ON p.pronamespace = n.oid
  WHERE n.nspname = 'public'
    AND p.proname IN (
      'refresh_nlp_views', 'get_similar_documents', 'get_document_topics'
    );

  RAISE NOTICE '========================================';
  RAISE NOTICE 'Sprint 3 NLP Schema Migration Complete!';
  RAISE NOTICE '========================================';
  RAISE NOTICE 'Tables created: %', table_count;
  RAISE NOTICE 'Materialized views created: %', view_count;
  RAISE NOTICE 'Helper functions created: %', function_count;
  RAISE NOTICE '';
  RAISE NOTICE 'Next steps:';
  RAISE NOTICE '1. Update Dockerfile with NLP R packages';
  RAISE NOTICE '2. Implement Word2Vec training functions';
  RAISE NOTICE '3. Run embedding generation batch jobs';
  RAISE NOTICE '========================================';
END $$;

-- Summary query
SELECT
  'document_embeddings' AS table_name,
  0 AS row_count,
  'Stores document embeddings (Word2Vec, GloVe, BERT)' AS description
UNION ALL
SELECT 'word_embeddings', 0, 'Vocabulary-level embeddings'
UNION ALL
SELECT 'semantic_similarity_cache', 0, 'Pre-computed similarity pairs'
UNION ALL
SELECT 'stm_models', 0, 'STM model metadata'
UNION ALL
SELECT 'stm_topics', 0, 'Topic definitions and labels'
UNION ALL
SELECT 'document_topics', 0, 'Document-topic proportions'
UNION ALL
SELECT 'stm_effects', 0, 'Covariate effects on topics'
UNION ALL
SELECT 'bert_embeddings', 0, 'BERT 768-dim embeddings'
ORDER BY table_name;
