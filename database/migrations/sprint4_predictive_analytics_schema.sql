-- Sprint 4: Predictive Analytics Schema
-- PRD 4.1: Survival Analysis for Bill Progression
-- PRD 4.2: Legislative Voting Behavior Prediction
-- Created: 2025-11-16

-- =====================================================
-- PRD 4.1: Bill Lifecycle Events for Survival Analysis
-- =====================================================

-- Track bill progression through legislative stages
CREATE TABLE IF NOT EXISTS bill_events (
  id SERIAL PRIMARY KEY,
  bill_id TEXT NOT NULL,  -- API bill identifier (e.g., "PL 1234/2023")
  event_type TEXT NOT NULL CHECK (event_type IN (
    'introduced',
    'committee_assigned',
    'committee_approved',
    'committee_rejected',
    'floor_scheduled',
    'floor_voted',
    'passed',
    'rejected',
    'withdrawn',
    'enacted'
  )),
  event_date DATE NOT NULL,
  days_since_introduction INTEGER,
  committee_name TEXT,
  description TEXT,
  vote_result TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(bill_id, event_type, event_date)
);

CREATE INDEX idx_bill_events_bill ON bill_events(bill_id);
CREATE INDEX idx_bill_events_type ON bill_events(event_type);
CREATE INDEX idx_bill_events_date ON bill_events(event_date);

COMMENT ON TABLE bill_events IS 'Tracks bill lifecycle events for survival analysis';
COMMENT ON COLUMN bill_events.days_since_introduction IS 'Time duration since bill introduction (calculated field)';

-- =====================================================
-- PRD 4.2: Legislators and Voting Records
-- =====================================================

-- Legislators table
CREATE TABLE IF NOT EXISTS legislators (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  party TEXT,
  state TEXT,
  position TEXT,
  term_start DATE,
  term_end DATE,
  email TEXT,
  photo_url TEXT,
  dw_nominate_1 NUMERIC,
  dw_nominate_2 NUMERIC,
  ideology_updated_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_legislators_party ON legislators(party);
CREATE INDEX idx_legislators_state ON legislators(state);

COMMENT ON TABLE legislators IS 'Information about legislators for voting prediction';
COMMENT ON COLUMN legislators.dw_nominate_1 IS 'First dimension of DW-NOMINATE ideal point (liberal-conservative)';
COMMENT ON COLUMN legislators.dw_nominate_2 IS 'Second dimension of DW-NOMINATE ideal point';

-- Roll call votes
CREATE TABLE IF NOT EXISTS roll_call_votes (
  id SERIAL PRIMARY KEY,
  bill_id TEXT NOT NULL,  -- API bill identifier (e.g., "PL 1234/2023")
  legislator_id TEXT REFERENCES legislators(id) ON DELETE CASCADE,
  vote TEXT NOT NULL CHECK (vote IN ('yes', 'no', 'abstain', 'absent')),
  vote_date DATE NOT NULL,
  session_number INTEGER,
  party_position TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(bill_id, legislator_id, vote_date)
);

CREATE INDEX idx_roll_call_bill ON roll_call_votes(bill_id);
CREATE INDEX idx_roll_call_legislator ON roll_call_votes(legislator_id);
CREATE INDEX idx_roll_call_date ON roll_call_votes(vote_date);
CREATE INDEX idx_roll_call_vote ON roll_call_votes(vote);

COMMENT ON TABLE roll_call_votes IS 'Individual legislator votes on bills';

-- =====================================================
-- Survival Analysis Results Cache
-- =====================================================

CREATE TABLE IF NOT EXISTS survival_analysis_results (
  id SERIAL PRIMARY KEY,
  bill_id TEXT NOT NULL,  -- API bill identifier (e.g., "PL 1234/2023")
  model_type TEXT NOT NULL CHECK (model_type IN ('kaplan_meier', 'cox', 'weibull', 'lognormal', 'gompertz')),
  predicted_passage_prob NUMERIC,
  predicted_days_to_passage INTEGER,
  hazard_ratio NUMERIC,
  confidence_interval_lower NUMERIC,
  confidence_interval_upper NUMERIC,
  calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  model_version TEXT
);

CREATE INDEX idx_survival_results_bill ON survival_analysis_results(bill_id);
CREATE INDEX idx_survival_results_model ON survival_analysis_results(model_type);

COMMENT ON TABLE survival_analysis_results IS 'Cached survival analysis predictions for bills';

-- =====================================================
-- Voting Prediction Results Cache
-- =====================================================

CREATE TABLE IF NOT EXISTS voting_predictions (
  id SERIAL PRIMARY KEY,
  bill_id TEXT NOT NULL,  -- API bill identifier (e.g., "PL 1234/2023")
  legislator_id TEXT REFERENCES legislators(id) ON DELETE CASCADE,
  predicted_vote TEXT CHECK (predicted_vote IN ('yes', 'no', 'abstain')),
  prediction_probability NUMERIC,
  model_type TEXT NOT NULL CHECK (model_type IN ('xgboost', 'logistic', 'random_forest')),
  predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  model_version TEXT,
  UNIQUE(bill_id, legislator_id, model_type)
);

CREATE INDEX idx_voting_predictions_bill ON voting_predictions(bill_id);
CREATE INDEX idx_voting_predictions_legislator ON voting_predictions(legislator_id);
CREATE INDEX idx_voting_predictions_model ON voting_predictions(model_type);

COMMENT ON TABLE voting_predictions IS 'Cached voting behavior predictions';

-- =====================================================
-- Bill Passage Predictions Aggregate
-- =====================================================

CREATE TABLE IF NOT EXISTS bill_passage_predictions (
  id SERIAL PRIMARY KEY,
  bill_id TEXT NOT NULL UNIQUE,  -- API bill identifier (e.g., "PL 1234/2023")
  predicted_yes_votes INTEGER,
  predicted_no_votes INTEGER,
  predicted_passage_prob NUMERIC,
  survival_passage_prob NUMERIC,
  combined_score NUMERIC,
  predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  model_version TEXT
);

CREATE INDEX idx_passage_predictions_bill ON bill_passage_predictions(bill_id);
CREATE INDEX idx_passage_predictions_prob ON bill_passage_predictions(predicted_passage_prob);

COMMENT ON TABLE bill_passage_predictions IS 'Aggregate bill passage predictions combining voting and survival models';

-- =====================================================
-- Views for Analysis
-- =====================================================

-- Bill lifecycle summary view
-- NOTE: Commented out because it references documentos table which doesn't exist in this database
-- This view can be recreated later when integrating with the main documentos table
-- CREATE OR REPLACE VIEW bill_lifecycle_summary AS
-- SELECT
--   d.id AS bill_id,
--   d.titulo,
--   d.tipo_documento,
--   d.nivel,
--   d.poder,
--   d.data_publicacao,
--   COUNT(DISTINCT be.event_type) AS num_events,
--   MIN(CASE WHEN be.event_type = 'introduced' THEN be.event_date END) AS intro_date,
--   MAX(CASE WHEN be.event_type IN ('passed', 'enacted') THEN be.event_date END) AS passage_date,
--   MAX(CASE WHEN be.event_type IN ('rejected', 'withdrawn') THEN be.event_date END) AS failure_date,
--   MAX(CASE WHEN be.event_type IN ('passed', 'enacted') THEN be.days_since_introduction END) AS days_to_passage,
--   CASE
--     WHEN MAX(CASE WHEN be.event_type IN ('passed', 'enacted') THEN 1 ELSE 0 END) = 1 THEN 'passed'
--     WHEN MAX(CASE WHEN be.event_type IN ('rejected', 'withdrawn') THEN 1 ELSE 0 END) = 1 THEN 'failed'
--     ELSE 'pending'
--   END AS status
-- FROM documentos d
-- LEFT JOIN bill_events be ON d.id = be.bill_id
-- GROUP BY d.id, d.titulo, d.tipo_documento, d.nivel, d.poder, d.data_publicacao;

-- COMMENT ON VIEW bill_lifecycle_summary IS 'Summary of bill lifecycle for survival analysis';

-- Legislator voting patterns view
CREATE OR REPLACE VIEW legislator_voting_patterns AS
SELECT
  l.id AS legislator_id,
  l.name,
  l.party,
  l.state,
  COUNT(*) AS total_votes,
  COUNT(CASE WHEN rcv.vote = 'yes' THEN 1 END) AS yes_votes,
  COUNT(CASE WHEN rcv.vote = 'no' THEN 1 END) AS no_votes,
  COUNT(CASE WHEN rcv.vote = 'abstain' THEN 1 END) AS abstain_votes,
  COUNT(CASE WHEN rcv.vote = 'absent' THEN 1 END) AS absent_votes,
  ROUND(COUNT(CASE WHEN rcv.vote = 'yes' THEN 1 END)::NUMERIC / NULLIF(COUNT(*), 0) * 100, 2) AS yes_percentage,
  l.dw_nominate_1,
  l.dw_nominate_2
FROM legislators l
LEFT JOIN roll_call_votes rcv ON l.id = rcv.legislator_id
GROUP BY l.id, l.name, l.party, l.state, l.dw_nominate_1, l.dw_nominate_2;

COMMENT ON VIEW legislator_voting_patterns IS 'Voting behavior patterns for each legislator';

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON bill_events TO monitor_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON legislators TO monitor_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON roll_call_votes TO monitor_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON survival_analysis_results TO monitor_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON voting_predictions TO monitor_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON bill_passage_predictions TO monitor_user;
-- GRANT SELECT ON bill_lifecycle_summary TO monitor_user;  -- Commented out (view doesn't exist)
GRANT SELECT ON legislator_voting_patterns TO monitor_user;

GRANT USAGE, SELECT ON SEQUENCE bill_events_id_seq TO monitor_user;
GRANT USAGE, SELECT ON SEQUENCE roll_call_votes_id_seq TO monitor_user;
GRANT USAGE, SELECT ON SEQUENCE survival_analysis_results_id_seq TO monitor_user;
GRANT USAGE, SELECT ON SEQUENCE voting_predictions_id_seq TO monitor_user;
GRANT USAGE, SELECT ON SEQUENCE bill_passage_predictions_id_seq TO monitor_user;
