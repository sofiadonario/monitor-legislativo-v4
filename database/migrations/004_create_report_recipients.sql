-- ==============================================================================
-- REPORT RECIPIENTS TABLE
-- ==============================================================================
-- Stores email recipients for automated legislative reports
-- Week 3 - Task 3.4
--
-- Author: Monitor Legislativo Team
-- Date: 2025-11-27
-- ==============================================================================

-- Create report_recipients table
CREATE TABLE IF NOT EXISTS report_recipients (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    role VARCHAR(100),
    organization VARCHAR(255),

    -- Report preferences
    daily_reports BOOLEAN DEFAULT TRUE,
    weekly_reports BOOLEAN DEFAULT TRUE,
    monthly_reports BOOLEAN DEFAULT FALSE,
    urgent_alerts BOOLEAN DEFAULT TRUE,

    -- Format preferences
    prefer_pdf BOOLEAN DEFAULT TRUE,
    prefer_html BOOLEAN DEFAULT FALSE,

    -- Status
    active BOOLEAN DEFAULT TRUE,
    verified BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_email_sent TIMESTAMP,
    email_count INTEGER DEFAULT 0,

    -- Notes
    notes TEXT
);

-- Create indexes
CREATE INDEX idx_recipients_email ON report_recipients(email);
CREATE INDEX idx_recipients_active ON report_recipients(active);
CREATE INDEX idx_recipients_daily ON report_recipients(daily_reports) WHERE active = TRUE;
CREATE INDEX idx_recipients_weekly ON report_recipients(weekly_reports) WHERE active = TRUE;
CREATE INDEX idx_recipients_monthly ON report_recipients(monthly_reports) WHERE active = TRUE;

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_recipients_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_recipients_updated_at
    BEFORE UPDATE ON report_recipients
    FOR EACH ROW
    EXECUTE FUNCTION update_recipients_updated_at();

-- Insert default recipient (account owner)
INSERT INTO report_recipients (
    email,
    name,
    role,
    organization,
    daily_reports,
    weekly_reports,
    monthly_reports,
    urgent_alerts,
    active,
    verified,
    notes
) VALUES (
    'sofiadonario@hotmail.com',
    'Sofia Donario',
    'Administrator',
    'Universidade Presbiteriana Mackenzie',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    'Account owner - receives all reports'
) ON CONFLICT (email) DO NOTHING;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON report_recipients TO monitor_user;
GRANT USAGE, SELECT ON SEQUENCE report_recipients_id_seq TO monitor_user;

-- Create view for active recipients by report type
CREATE OR REPLACE VIEW v_daily_recipients AS
SELECT email, name, prefer_pdf, prefer_html
FROM report_recipients
WHERE active = TRUE AND daily_reports = TRUE AND verified = TRUE;

CREATE OR REPLACE VIEW v_weekly_recipients AS
SELECT email, name, prefer_pdf, prefer_html
FROM report_recipients
WHERE active = TRUE AND weekly_reports = TRUE AND verified = TRUE;

CREATE OR REPLACE VIEW v_monthly_recipients AS
SELECT email, name, prefer_pdf, prefer_html
FROM report_recipients
WHERE active = TRUE AND monthly_reports = TRUE AND verified = TRUE;

GRANT SELECT ON v_daily_recipients TO monitor_user;
GRANT SELECT ON v_weekly_recipients TO monitor_user;
GRANT SELECT ON v_monthly_recipients TO monitor_user;

-- Success message
DO $$
BEGIN
    RAISE NOTICE '✅ Report recipients table created successfully';
    RAISE NOTICE '   - Default recipient added: sofiadonario@hotmail.com';
    RAISE NOTICE '   - Views created for daily/weekly/monthly recipients';
    RAISE NOTICE '   - Indexes and triggers configured';
END $$;
