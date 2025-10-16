-- ============================================================================
-- DEMOGRAPHICS AND BILLS PER CAPITA MIGRATION
-- ============================================================================
-- Adds Brazilian state demographics and bills per 100k population metric
-- for choropleth map visualization

-- Drop existing objects if they exist (for safe re-runs)
DROP MATERIALIZED VIEW IF EXISTS mv_docs_state_density CASCADE;
DROP TABLE IF EXISTS demographics CASCADE;

-- ============================================================================
-- DEMOGRAPHICS TABLE
-- ============================================================================
-- Population data for Brazilian states by year
-- Source: IBGE (Instituto Brasileiro de Geografia e Estatística)

CREATE TABLE demographics (
    state VARCHAR(2) NOT NULL,
    year INTEGER NOT NULL,
    population BIGINT NOT NULL,
    source VARCHAR(100) DEFAULT 'IBGE',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (state, year),
    CONSTRAINT valid_state CHECK (state IN (
        'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA',
        'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN',
        'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO'
    )),
    CONSTRAINT valid_year CHECK (year >= 1900 AND year <= 2100),
    CONSTRAINT positive_population CHECK (population > 0)
);

-- Create index for efficient lookups
CREATE INDEX idx_demographics_year ON demographics(year);
CREATE INDEX idx_demographics_state ON demographics(state);

-- Add comment
COMMENT ON TABLE demographics IS 'Brazilian state population data by year (source: IBGE)';

-- ============================================================================
-- POPULATE DEMOGRAPHICS DATA
-- ============================================================================
-- Population estimates for Brazilian states (2020-2024)
-- Source: IBGE population estimates

INSERT INTO demographics (state, year, population) VALUES
-- 2020 data
('AC', 2020, 894470),
('AL', 2020, 3351543),
('AP', 2020, 861773),
('AM', 2020, 4207714),
('BA', 2020, 14930634),
('CE', 2020, 9187103),
('DF', 2020, 3055149),
('ES', 2020, 4064052),
('GO', 2020, 7113540),
('MA', 2020, 7114598),
('MT', 2020, 3526220),
('MS', 2020, 2809394),
('MG', 2020, 21292666),
('PA', 2020, 8690745),
('PB', 2020, 4039277),
('PR', 2020, 11516840),
('PE', 2020, 9616621),
('PI', 2020, 3281480),
('RJ', 2020, 17366189),
('RN', 2020, 3534165),
('RS', 2020, 11422973),
('RO', 2020, 1796460),
('RR', 2020, 631181),
('SC', 2020, 7252502),
('SP', 2020, 46289333),
('SE', 2020, 2318822),
('TO', 2020, 1590248),

-- 2021 data
('AC', 2021, 906876),
('AL', 2021, 3365351),
('AP', 2021, 877613),
('AM', 2021, 4269995),
('BA', 2021, 14985284),
('CE', 2021, 9240580),
('DF', 2021, 3094325),
('ES', 2021, 4108508),
('GO', 2021, 7206589),
('MA', 2021, 7153262),
('MT', 2021, 3567234),
('MS', 2021, 2839188),
('MG', 2021, 21411923),
('PA', 2021, 8777124),
('PB', 2021, 4059905),
('PR', 2021, 11597484),
('PE', 2021, 9674793),
('PI', 2021, 3289290),
('RJ', 2021, 17463349),
('RN', 2021, 3560903),
('RS', 2021, 11466630),
('RO', 2021, 1815278),
('RR', 2021, 652713),
('SC', 2021, 7338473),
('SP', 2021, 46649132),
('SE', 2021, 2338474),
('TO', 2021, 1607363),

-- 2022 data
('AC', 2022, 906876),
('AL', 2022, 3365351),
('AP', 2022, 877613),
('AM', 2022, 4269995),
('BA', 2022, 14985284),
('CE', 2022, 9240580),
('DF', 2022, 3094325),
('ES', 2022, 4108508),
('GO', 2022, 7206589),
('MA', 2022, 7153262),
('MT', 2022, 3567234),
('MS', 2022, 2839188),
('MG', 2022, 21411923),
('PA', 2022, 8777124),
('PB', 2022, 4059905),
('PR', 2022, 11597484),
('PE', 2022, 9674793),
('PI', 2022, 3289290),
('RJ', 2022, 17463349),
('RN', 2022, 3560903),
('RS', 2022, 11466630),
('RO', 2022, 1815278),
('RR', 2022, 652713),
('SC', 2022, 7338473),
('SP', 2022, 46649132),
('SE', 2022, 2338474),
('TO', 2022, 1607363),

-- 2023 data
('AC', 2023, 830026),
('AL', 2023, 3127683),
('AP', 2023, 733508),
('AM', 2023, 3952262),
('BA', 2023, 14141626),
('CE', 2023, 8794957),
('DF', 2023, 2817068),
('ES', 2023, 3833712),
('GO', 2023, 6950976),
('MA', 2023, 6775152),
('MT', 2023, 3236578),
('MS', 2023, 2757013),
('MG', 2023, 20539989),
('PA', 2023, 8121025),
('PB', 2023, 3766834),
('PR', 2023, 11444380),
('PE', 2023, 9058931),
('PI', 2023, 3210865),
('RJ', 2023, 16615526),
('RN', 2023, 3303953),
('RS', 2023, 10882965),
('RO', 2023, 1657996),
('RR', 2023, 634805),
('SC', 2023, 7610361),
('SP', 2023, 44411238),
('SE', 2023, 2210004),
('TO', 2023, 1511460),

-- 2024 data (projections)
('AC', 2024, 830000),
('AL', 2024, 3127000),
('AP', 2024, 733000),
('AM', 2024, 3952000),
('BA', 2024, 14140000),
('CE', 2024, 8795000),
('DF', 2024, 2817000),
('ES', 2024, 3834000),
('GO', 2024, 6951000),
('MA', 2024, 6775000),
('MT', 2024, 3237000),
('MS', 2024, 2757000),
('MG', 2024, 20540000),
('PA', 2024, 8121000),
('PB', 2024, 3767000),
('PR', 2024, 11444000),
('PE', 2024, 9059000),
('PI', 2024, 3211000),
('RJ', 2024, 16616000),
('RN', 2024, 3304000),
('RS', 2024, 10883000),
('RO', 2024, 1658000),
('RR', 2024, 635000),
('SC', 2024, 7610000),
('SP', 2024, 44411000),
('SE', 2024, 2210000),
('TO', 2024, 1511000);

-- ============================================================================
-- MATERIALIZED VIEW: BILLS PER 100K POPULATION
-- ============================================================================
-- Calculates legislative bills per 100,000 inhabitants by state and year
-- Joins document counts with population demographics

CREATE MATERIALIZED VIEW mv_docs_state_density AS
SELECT
    s.state,
    s.year,
    s.n_docs,
    d.population,
    ROUND((s.n_docs::numeric / d.population::numeric * 100000), 2) AS bills_per_100k
FROM mv_docs_state_year s
INNER JOIN demographics d
    ON s.state = d.state
    AND s.year = d.year
WHERE s.state IS NOT NULL
ORDER BY s.year DESC, bills_per_100k DESC;

-- Create index for fast lookups
CREATE INDEX idx_mv_docs_state_density_state ON mv_docs_state_density(state);
CREATE INDEX idx_mv_docs_state_density_year ON mv_docs_state_density(year);
CREATE INDEX idx_mv_docs_state_density_rate ON mv_docs_state_density(bills_per_100k DESC);

-- Add comment
COMMENT ON MATERIALIZED VIEW mv_docs_state_density IS
    'Legislative bills per 100k population by state and year';

-- ============================================================================
-- REFRESH FUNCTION
-- ============================================================================
-- Helper function to refresh the density view

CREATE OR REPLACE FUNCTION refresh_density_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_density;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_density_view() IS
    'Refresh bills per 100k population materialized view';

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify demographics data
SELECT 'Demographics table populated' AS status, COUNT(*) AS total_rows
FROM demographics;

-- Verify density view
SELECT 'Density view created' AS status, COUNT(*) AS total_rows
FROM mv_docs_state_density;

-- Sample density data (top 10 states by bills per 100k in 2023)
SELECT
    state,
    year,
    n_docs AS total_bills,
    population,
    bills_per_100k
FROM mv_docs_state_density
WHERE year = 2023
ORDER BY bills_per_100k DESC
LIMIT 10;

-- ============================================================================
-- USAGE NOTES
-- ============================================================================
--
-- To refresh the density view after new data ingestion:
--   SELECT refresh_density_view();
--   -- or --
--   REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_density;
--
-- To query bills per capita:
--   SELECT * FROM mv_docs_state_density WHERE year = 2024;
--
-- To update population data for a new year:
--   INSERT INTO demographics (state, year, population)
--   VALUES ('SP', 2025, 44500000);
--   SELECT refresh_density_view();
--
-- ============================================================================
