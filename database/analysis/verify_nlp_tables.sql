-- Sprint 3 NLP Database Verification Queries
-- Run after batch jobs complete to verify data population

\echo '================================================'
\echo 'SPRINT 3 NLP DATA VERIFICATION'
\echo '================================================'

\echo ''
\echo '--- 1. READABILITY METRICS ---'
SELECT 
  COUNT(*) as total_documents,
  COUNT(CASE WHEN flesch_reading_ease IS NOT NULL THEN 1 END) as flesch_count,
  COUNT(CASE WHEN flesch_kincaid_grade IS NOT NULL THEN 1 END) as fk_count,
  COUNT(CASE WHEN gunning_fog IS NOT NULL THEN 1 END) as gunning_count,
  COUNT(CASE WHEN smog_index IS NOT NULL THEN 1 END) as smog_count,
  ROUND(AVG(flesch_reading_ease)::numeric, 2) as avg_flesch,
  ROUND(AVG(flesch_kincaid_grade)::numeric, 2) as avg_fk_grade
FROM readability_metrics;

\echo ''
\echo '--- 2. WORD EMBEDDINGS ---'
SELECT 
  COUNT(*) as total_embeddings,
  COUNT(DISTINCT documento_id) as unique_documents,
  MIN(created_at) as first_embedding,
  MAX(created_at) as last_embedding
FROM word_embeddings;

\echo ''
\echo '--- 3. TOPIC MODELS ---'
SELECT 
  model_type,
  model_version,
  n_topics,
  vocabulary_size,
  training_docs,
  trained_at
FROM topic_models
ORDER BY trained_at DESC;

\echo ''
\echo '--- 4. DOCUMENT TOPICS ---'
SELECT 
  topic_id,
  COUNT(*) as doc_count,
  ROUND(AVG(proportion)::numeric, 3) as avg_proportion,
  ROUND(MIN(proportion)::numeric, 3) as min_proportion,
  ROUND(MAX(proportion)::numeric, 3) as max_proportion
FROM document_topics
GROUP BY topic_id
ORDER BY topic_id;

\echo ''
\echo '--- 5. NLP MODELS METADATA ---'
SELECT 
  model_type,
  model_version,
  vocabulary_size,
  vector_dimensions,
  training_docs,
  trained_at
FROM nlp_models
ORDER BY trained_at DESC;

\echo ''
\echo '--- 6. SAMPLE READABILITY SCORES ---'
SELECT 
  d.id,
  LEFT(d.titulo, 60) as titulo,
  r.flesch_reading_ease,
  r.flesch_kincaid_grade,
  CASE 
    WHEN r.flesch_reading_ease >= 90 THEN 'Very Easy'
    WHEN r.flesch_reading_ease >= 80 THEN 'Easy'
    WHEN r.flesch_reading_ease >= 70 THEN 'Fairly Easy'
    WHEN r.flesch_reading_ease >= 60 THEN 'Standard'
    WHEN r.flesch_reading_ease >= 50 THEN 'Fairly Difficult'
    WHEN r.flesch_reading_ease >= 30 THEN 'Difficult'
    ELSE 'Very Difficult'
  END as readability_level
FROM documentos d
JOIN readability_metrics r ON d.id = r.documento_id
WHERE r.flesch_reading_ease IS NOT NULL
ORDER BY r.flesch_reading_ease DESC
LIMIT 10;

\echo ''
\echo '================================================'
\echo 'VERIFICATION COMPLETE'
\echo '================================================'
