# Product Requirements Document: BI Enhancements & External Dashboard Integration

**Document Version:** 1.0
**Date:** 2025-11-25
**Author:** Claude AI Assistant
**Status:** Draft - Pending Review

---

## Executive Summary

This PRD outlines the strategy for enhancing the Monitor Legislativo platform with Business Intelligence (BI) capabilities to deliver:

1. **Real-time monitoring dashboards** for system health and legislative activity tracking
2. **Polished executive reports** shareable with non-technical stakeholders
3. **Self-service analytics** for ad-hoc data exploration

The implementation follows a two-phase approach: first enhancing the existing R/Shiny infrastructure, then integrating external BI tools (Grafana for monitoring, Metabase for exploration, Looker Studio for sharing).

---

## Problem Statement

### Current State
- The platform has powerful R/Shiny dashboards with 134,000+ legislative documents
- Existing visualizations are developer-focused, not executive-ready
- No real-time monitoring capabilities for system health
- Reports cannot be easily shared with non-technical users outside the platform
- No self-service SQL exploration for researchers

### User Pain Points
| User Type | Pain Point |
|-----------|------------|
| **Executives/Stakeholders** | Cannot access quick summary reports without logging into the full application |
| **Operations Team** | No real-time alerts or monitoring dashboards for system health |
| **Researchers** | Cannot run ad-hoc SQL queries without developer assistance |
| **External Partners** | No way to receive scheduled/automated reports |

---

## Goals & Objectives

### Primary Goals
1. Enable non-technical users to consume legislative insights via polished, shareable reports
2. Implement real-time monitoring with alerting for system health and data pipeline status
3. Provide self-service analytics for power users without requiring R knowledge

### Success Metrics
| Metric | Target | Measurement |
|--------|--------|-------------|
| Executive report generation time | < 5 seconds | Automated timing |
| Dashboard load time | < 3 seconds | Performance monitoring |
| Report sharing adoption | 50+ shares/month | Usage tracking |
| Alert response time | < 15 minutes | Incident tracking |
| Self-service query adoption | 20+ queries/week | Metabase analytics |

---

## Solution Overview

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Monitor Legislativo v4                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │   PostgreSQL    │───▶│   R/Shiny App   │───▶│  Enhanced BI    │     │
│  │   (Primary DB)  │    │   (Existing)    │    │   Dashboards    │     │
│  └────────┬────────┘    └─────────────────┘    └─────────────────┘     │
│           │                                                             │
│           │  ┌──────────────────────────────────────────────────────┐  │
│           │  │              External BI Layer                        │  │
│           │  ├──────────────────────────────────────────────────────┤  │
│           │  │                                                       │  │
│           ├──┼──▶ ┌─────────────┐  Real-time monitoring, alerts     │  │
│           │  │    │   Grafana   │  System health, pipeline status   │  │
│           │  │    └─────────────┘                                    │  │
│           │  │                                                       │  │
│           ├──┼──▶ ┌─────────────┐  Self-service SQL exploration     │  │
│           │  │    │  Metabase   │  Ad-hoc queries, saved questions  │  │
│           │  │    └─────────────┘                                    │  │
│           │  │                                                       │  │
│           └──┼──▶ ┌─────────────┐  Executive reports, sharing       │  │
│              │    │Looker Studio│  Scheduled reports, embedding     │  │
│              │    └─────────────┘                                    │  │
│              └──────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Enhance Existing R/Shiny with BI-Like Features

### 1.1 Executive Dashboard Module

**Objective:** Create a dedicated executive-focused dashboard within Shiny

#### Requirements

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| EX-01 | One-page executive summary with KPIs | P0 | Load in < 3 seconds |
| EX-02 | Key metrics: document count, growth rate, coverage by jurisdiction | P0 | Auto-refresh every 5 min |
| EX-03 | Trend sparklines for 30/60/90 day periods | P0 | Minimal design |
| EX-04 | Top 5 most active states visualization | P1 | Horizontal bar chart |
| EX-05 | Recent legislative highlights (last 7 days) | P1 | Card-based layout |
| EX-06 | Print-optimized CSS for PDF export | P0 | A4/Letter format |
| EX-07 | Branded header/footer for reports | P1 | Configurable logo |

#### UI/UX Specifications

```
┌─────────────────────────────────────────────────────────────────┐
│  MONITOR LEGISLATIVO - Executive Summary        [Export PDF] 📥 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  134,014 │  │  +2,847  │  │    27    │  │   89%    │        │
│  │Documents │  │This Month│  │  States  │  │ Coverage │        │
│  │   📊     │  │   📈     │  │   🗺️     │  │   ✓      │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                                                  │
│  Document Growth (90 days)          Top States by Activity      │
│  ┌─────────────────────────┐       ┌─────────────────────────┐  │
│  │    ╱──────────╲         │       │ SP ████████████ 28,451  │  │
│  │   ╱            ╲        │       │ RJ █████████    19,283  │  │
│  │  ╱              ────    │       │ MG ████████     15,672  │  │
│  │ ╱                       │       │ BA ██████       12,104  │  │
│  └─────────────────────────┘       │ RS █████         9,847  │  │
│                                    └─────────────────────────┘  │
│                                                                  │
│  Recent Highlights                                               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 📋 Lei 14.XXX - Federal transportation regulation update    ││
│  │ 📋 Decreto YYYY - São Paulo mobility framework              ││
│  │ 📋 Portaria ZZZ - ANTT regulatory change                    ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Generated: 2025-11-25 14:30 BRT    Data freshness: 2 hours ago │
└─────────────────────────────────────────────────────────────────┘
```

#### Technical Implementation

**New Files to Create:**
- `R/ui/executive_summary_ui.R` - UI components
- `R/modules/executive_summary_server.R` - Server logic
- `R/utils/report_generator.R` - PDF/HTML export utilities
- `inst/www/css/executive_print.css` - Print-optimized styles

**Data Requirements:**
```sql
-- Executive dashboard pre-aggregated view
CREATE MATERIALIZED VIEW mv_executive_summary AS
SELECT
    COUNT(*) as total_documents,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') as last_30_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') as last_7_days,
    COUNT(DISTINCT estado) as states_covered,
    COUNT(DISTINCT tipo_documento) as document_types
FROM documents;

-- Refresh every hour
CREATE INDEX idx_exec_summary_refresh ON mv_executive_summary(...);
```

---

### 1.2 Real-Time Activity Feed

**Objective:** Show live legislative activity within Shiny

#### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| RT-01 | WebSocket-based live updates | P1 |
| RT-02 | Activity stream showing new documents | P0 |
| RT-03 | Filterable by jurisdiction/type | P1 |
| RT-04 | "X documents added in last hour" indicator | P0 |
| RT-05 | Notification badges for significant changes | P2 |

#### Technical Implementation

**Using Shiny's reactiveTimer or shinyjs for polling:**
```r
# Pseudo-code structure
observe({
  invalidateLater(30000)  # 30-second refresh
  activity_data <- get_recent_activity(minutes = 60)
  output$activity_feed <- renderUI({ ... })
})
```

---

### 1.3 Shareable Report Links

**Objective:** Generate standalone HTML reports that can be shared via URL

#### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| SH-01 | Generate static HTML snapshot of any dashboard view | P0 |
| SH-02 | Unique shareable URL per report | P0 |
| SH-03 | Expiration settings (7/30/90 days) | P1 |
| SH-04 | Password protection option | P2 |
| SH-05 | Download as PDF option | P0 |

#### Technical Implementation

**New Files:**
- `R/modules/report_sharing_module.R`
- `R/utils/static_report_generator.R`

**Storage:**
- Generated reports stored in cloud storage (GCS/S3)
- Metadata tracked in PostgreSQL `shared_reports` table

---

### 1.4 Scheduled Report Delivery

**Objective:** Automated report generation and email delivery

#### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| SC-01 | Configure daily/weekly/monthly schedules | P1 |
| SC-02 | Email delivery with PDF attachment | P1 |
| SC-03 | Recipient management UI | P1 |
| SC-04 | Report customization (sections to include) | P2 |

#### Technical Implementation

**Using GitHub Actions or Cloud Scheduler:**
```yaml
# .github/workflows/scheduled-reports.yml
name: Generate Executive Reports
on:
  schedule:
    - cron: '0 8 * * 1'  # Every Monday at 8am
jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate Report
        run: Rscript scripts/generate_executive_report.R
      - name: Send Email
        uses: dawidd6/action-send-mail@v3
```

---

## Phase 2: External BI Tools Integration

### 2.1 Grafana - Real-Time Monitoring

**Purpose:** System health monitoring, pipeline status, real-time alerts

#### Dashboard Specifications

**Dashboard 1: System Health**
| Panel | Visualization | Data Source |
|-------|---------------|-------------|
| API Response Time | Time series | PostgreSQL / Prometheus |
| Database Connections | Gauge | PostgreSQL |
| Memory Usage | Time series | System metrics |
| Error Rate | Stat + Threshold | Application logs |
| Active Users | Stat | Session table |

**Dashboard 2: Data Pipeline Status**
| Panel | Visualization | Data Source |
|-------|---------------|-------------|
| Documents Ingested (24h) | Stat | PostgreSQL |
| Ingestion Rate | Time series | PostgreSQL |
| Failed Scrapes | Table | PostgreSQL |
| Source Health | Status map | API health checks |
| Queue Depth | Gauge | Job queue table |

**Dashboard 3: Legislative Activity**
| Panel | Visualization | Data Source |
|-------|---------------|-------------|
| Documents by Hour | Heatmap | PostgreSQL |
| Geographic Activity | Geomap | PostgreSQL |
| Top Document Types | Pie chart | PostgreSQL |
| Trending Topics | Word cloud | PostgreSQL |

#### Alert Rules

| Alert | Condition | Severity | Channel |
|-------|-----------|----------|---------|
| High Error Rate | > 5% errors in 5 min | Critical | Slack, Email |
| Database Connection Pool | > 80% utilized | Warning | Slack |
| Ingestion Stopped | 0 documents in 2 hours | Critical | Slack, Email, SMS |
| API Latency | p95 > 2s for 10 min | Warning | Slack |

#### Setup Requirements

**Docker Compose Addition:**
```yaml
# docker-compose.grafana.yml
services:
  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_INSTALL_PLUGINS=grafana-worldmap-panel
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards

volumes:
  grafana_data:
```

**PostgreSQL Data Source Configuration:**
```yaml
# grafana/provisioning/datasources/postgresql.yml
apiVersion: 1
datasources:
  - name: PostgreSQL
    type: postgres
    url: ${DB_HOST}:5432
    database: ${DB_NAME}
    user: ${DB_USER}
    secureJsonData:
      password: ${DB_PASSWORD}
    jsonData:
      sslmode: require
      maxOpenConns: 5
      maxIdleConns: 2
```

---

### 2.2 Metabase - Self-Service Analytics

**Purpose:** Ad-hoc SQL exploration, saved questions, internal data exploration

#### Configuration

**Pre-built Questions (Saved Queries):**

1. **Document Growth Over Time**
```sql
SELECT
    DATE_TRUNC('month', data_publicacao) as month,
    COUNT(*) as documents,
    nivel as jurisdiction
FROM documents
WHERE data_publicacao >= NOW() - INTERVAL '2 years'
GROUP BY 1, 2
ORDER BY 1
```

2. **Top Producing Entities**
```sql
SELECT
    orgao_emissor as entity,
    COUNT(*) as document_count,
    COUNT(DISTINCT tipo_documento) as document_types
FROM documents
GROUP BY 1
ORDER BY 2 DESC
LIMIT 20
```

3. **Document Type Distribution**
```sql
SELECT
    tipo_documento,
    nivel,
    COUNT(*) as count
FROM documents
GROUP BY 1, 2
```

4. **Geographic Coverage Analysis**
```sql
SELECT
    estado,
    COUNT(*) as total_documents,
    COUNT(*) FILTER (WHERE data_publicacao >= NOW() - INTERVAL '30 days') as last_30_days,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) as percentage
FROM documents
WHERE estado IS NOT NULL
GROUP BY 1
ORDER BY 2 DESC
```

#### Collections Structure
```
📁 Monitor Legislativo
├── 📁 Executive Dashboards
│   ├── 📊 Monthly Summary
│   ├── 📊 State Comparison
│   └── 📊 Growth Trends
├── 📁 Operational
│   ├── 📊 Data Quality Check
│   ├── 📊 Missing Data Report
│   └── 📊 Source Coverage
└── 📁 Research
    ├── 📊 Topic Analysis
    ├── 📊 Temporal Patterns
    └── 📊 Network Metrics
```

#### Setup Requirements

**Docker Compose Addition:**
```yaml
# docker-compose.metabase.yml
services:
  metabase:
    image: metabase/metabase:v0.47.0
    ports:
      - "3002:3000"
    environment:
      - MB_DB_TYPE=postgres
      - MB_DB_DBNAME=metabase
      - MB_DB_PORT=5432
      - MB_DB_USER=${MB_DB_USER}
      - MB_DB_PASS=${MB_DB_PASS}
      - MB_DB_HOST=${MB_DB_HOST}
    volumes:
      - metabase_data:/metabase-data

volumes:
  metabase_data:
```

**User Roles:**
| Role | Permissions |
|------|-------------|
| Admin | Full access, user management |
| Analyst | Create questions, dashboards |
| Viewer | View shared dashboards only |

---

### 2.3 Looker Studio - Executive Sharing

**Purpose:** Beautiful, shareable reports for non-technical stakeholders

#### Report Templates

**Template 1: Monthly Executive Report**
- Page 1: Key Metrics Summary (KPIs, trends)
- Page 2: Geographic Analysis (Brazil map, state breakdown)
- Page 3: Document Type Analysis (pie charts, trends)
- Page 4: Year-over-Year Comparison
- Page 5: Highlights & Recommendations (text + visuals)

**Template 2: State-Specific Report**
- Focus on single state metrics
- Comparison with national averages
- Local legislative highlights

**Template 3: Topic Deep-Dive**
- Filter by legislative topic (transportation, environment, etc.)
- Related documents timeline
- Key actors and entities

#### Data Connection

**Option A: Direct PostgreSQL Connection**
- Use Looker Studio PostgreSQL connector
- Read-only credentials
- Scheduled refresh (hourly/daily)

**Option B: BigQuery Intermediate Layer**
- Export aggregated data to BigQuery
- Better performance for large datasets
- Native Google integration

**Recommended Approach:** Option B for production

**Data Pipeline:**
```
PostgreSQL → Cloud Function (hourly) → BigQuery → Looker Studio
```

#### Sharing Configuration
| Audience | Access Level | Distribution |
|----------|--------------|--------------|
| Internal Team | Edit | Direct link |
| Executives | View | Scheduled email (PDF) |
| External Partners | View | Embedded iframe |
| Public | View | Published report |

---

## Implementation Plan

### Timeline Overview

```
Phase 1: Shiny BI Enhancements (Weeks 1-4)
├── Week 1: Executive Dashboard UI/UX
├── Week 2: Report Generation & Export
├── Week 3: Shareable Links & Scheduling
└── Week 4: Testing & Polish

Phase 2: External BI Tools (Weeks 5-8)
├── Week 5: Grafana Setup & Dashboards
├── Week 6: Metabase Setup & Questions
├── Week 7: Looker Studio Integration
└── Week 8: Documentation & Training
```

### Detailed Task Breakdown

#### Phase 1, Week 1: Executive Dashboard

| Task | Description | Files |
|------|-------------|-------|
| 1.1 | Create executive summary UI layout | `R/ui/executive_summary_ui.R` |
| 1.2 | Implement KPI calculation functions | `R/utils/kpi_calculations.R` |
| 1.3 | Build sparkline components | `R/components/sparklines.R` |
| 1.4 | Create materialized views for performance | `database/views/mv_executive.sql` |
| 1.5 | Add executive tab to main navigation | `R/ui/dashboard.R` |
| 1.6 | Style with executive-focused CSS | `inst/www/css/executive.css` |

#### Phase 1, Week 2: Report Generation

| Task | Description | Files |
|------|-------------|-------|
| 2.1 | PDF export using pagedown/chrome_print | `R/utils/pdf_generator.R` |
| 2.2 | HTML static report generator | `R/utils/html_report.R` |
| 2.3 | Print-optimized CSS | `inst/www/css/print.css` |
| 2.4 | Report templates (Quarto/RMarkdown) | `inst/templates/` |
| 2.5 | Export button integration | `R/modules/export_module.R` |

#### Phase 1, Week 3: Sharing & Scheduling

| Task | Description | Files |
|------|-------------|-------|
| 3.1 | Shareable link generation | `R/modules/share_module.R` |
| 3.2 | Cloud storage integration | `R/utils/cloud_storage.R` |
| 3.3 | Schedule configuration UI | `R/ui/schedule_config.R` |
| 3.4 | Email delivery integration | `R/utils/email_sender.R` |
| 3.5 | GitHub Actions workflow | `.github/workflows/reports.yml` |

#### Phase 1, Week 4: Testing & Polish

| Task | Description |
|------|-------------|
| 4.1 | Unit tests for report generation |
| 4.2 | Performance optimization |
| 4.3 | Cross-browser testing |
| 4.4 | Accessibility audit (WCAG 2.1 AA) |
| 4.5 | User acceptance testing |

#### Phase 2, Week 5: Grafana

| Task | Description | Files |
|------|-------------|-------|
| 5.1 | Docker compose configuration | `docker-compose.grafana.yml` |
| 5.2 | PostgreSQL data source setup | `grafana/provisioning/` |
| 5.3 | System health dashboard | `grafana/dashboards/system.json` |
| 5.4 | Pipeline monitoring dashboard | `grafana/dashboards/pipeline.json` |
| 5.5 | Alert rules configuration | `grafana/provisioning/alerting/` |
| 5.6 | Slack/Email notification channels | Config via UI |

#### Phase 2, Week 6: Metabase

| Task | Description | Files |
|------|-------------|-------|
| 6.1 | Docker compose configuration | `docker-compose.metabase.yml` |
| 6.2 | Database connection setup | Via UI |
| 6.3 | Create saved questions library | Via UI, export JSON |
| 6.4 | Build collection structure | Via UI |
| 6.5 | User roles and permissions | Via UI |
| 6.6 | Embedding configuration | Via UI |

#### Phase 2, Week 7: Looker Studio

| Task | Description |
|------|-------------|
| 7.1 | BigQuery dataset creation |
| 7.2 | Data sync Cloud Function |
| 7.3 | Monthly executive report template |
| 7.4 | State-specific report template |
| 7.5 | Sharing and scheduling configuration |
| 7.6 | Embedded report testing |

#### Phase 2, Week 8: Documentation & Training

| Task | Description | Files |
|------|-------------|-------|
| 8.1 | User guide for executives | `docs/guides/executive_guide.md` |
| 8.2 | Admin guide for BI tools | `docs/guides/bi_admin_guide.md` |
| 8.3 | Developer documentation | `docs/technical/bi_integration.md` |
| 8.4 | Video tutorials | External hosting |
| 8.5 | Training sessions | Calendar scheduling |

---

## Technical Requirements

### Infrastructure

| Component | Requirement | Notes |
|-----------|-------------|-------|
| Grafana | 512MB RAM, 1 CPU | Can share with existing infra |
| Metabase | 1GB RAM, 1 CPU | Separate container recommended |
| Looker Studio | N/A (SaaS) | Google account required |
| Cloud Storage | 10GB initial | For static reports |
| Email Service | SendGrid/SES | For scheduled delivery |

### Database Additions

```sql
-- New tables for BI features

-- Shared reports tracking
CREATE TABLE shared_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type VARCHAR(50) NOT NULL,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    access_token VARCHAR(64) UNIQUE NOT NULL,
    view_count INTEGER DEFAULT 0,
    storage_path TEXT NOT NULL,
    parameters JSONB,
    is_active BOOLEAN DEFAULT true
);

-- Scheduled reports configuration
CREATE TABLE scheduled_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    schedule_cron VARCHAR(100) NOT NULL,
    recipients TEXT[] NOT NULL,
    parameters JSONB,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Report delivery log
CREATE TABLE report_delivery_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scheduled_report_id UUID REFERENCES scheduled_reports(id),
    delivered_at TIMESTAMP DEFAULT NOW(),
    recipients TEXT[],
    status VARCHAR(20),
    error_message TEXT
);

-- Materialized view for executive dashboard
CREATE MATERIALIZED VIEW mv_executive_metrics AS
SELECT
    COUNT(*) as total_documents,
    COUNT(*) FILTER (WHERE data_publicacao >= CURRENT_DATE - INTERVAL '30 days') as docs_last_30_days,
    COUNT(*) FILTER (WHERE data_publicacao >= CURRENT_DATE - INTERVAL '7 days') as docs_last_7_days,
    COUNT(*) FILTER (WHERE data_publicacao >= CURRENT_DATE - INTERVAL '1 day') as docs_last_24h,
    COUNT(DISTINCT estado) as states_with_data,
    COUNT(DISTINCT tipo_documento) as document_types,
    MAX(data_publicacao) as latest_document_date,
    (SELECT COUNT(DISTINCT estado) FROM documents WHERE estado IS NOT NULL) * 100.0 / 27 as coverage_percentage
FROM documents;

-- Index for faster refresh
CREATE UNIQUE INDEX idx_mv_executive_metrics ON mv_executive_metrics (total_documents);

-- Refresh function
CREATE OR REPLACE FUNCTION refresh_executive_metrics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_executive_metrics;
END;
$$ LANGUAGE plpgsql;
```

### Environment Variables

```bash
# Add to .env.example

# Grafana
GRAFANA_ADMIN_PASSWORD=changeme
GRAFANA_PORT=3001

# Metabase
METABASE_PORT=3002
MB_DB_USER=metabase
MB_DB_PASS=changeme
MB_DB_HOST=localhost

# Report sharing
REPORT_STORAGE_BUCKET=monitor-legislativo-reports
REPORT_BASE_URL=https://reports.monitor-legislativo.com.br

# Email delivery
SENDGRID_API_KEY=your_key_here
REPORT_FROM_EMAIL=reports@monitor-legislativo.com.br

# Looker Studio (BigQuery)
BIGQUERY_PROJECT_ID=your_project
BIGQUERY_DATASET=monitor_legislativo
```

---

## Security Considerations

### Access Control

| Tool | Authentication | Authorization |
|------|----------------|---------------|
| Shiny Reports | Existing auth | Role-based |
| Grafana | OIDC/OAuth | Team-based |
| Metabase | Email/Password | Collection-based |
| Looker Studio | Google Account | Share settings |

### Data Protection

- All connections use TLS/SSL
- Database credentials stored in secrets manager
- Shared report links use cryptographic tokens
- Automatic expiration for shared content
- Audit logging for all access
- LGPD compliance maintained

### Network Security

```yaml
# Recommended: Internal network only
services:
  grafana:
    networks:
      - internal
    # Expose via reverse proxy only

  metabase:
    networks:
      - internal
    # Expose via reverse proxy only
```

---

## Success Criteria

### Phase 1 Completion Criteria
- [ ] Executive dashboard loads in < 3 seconds
- [ ] PDF export generates correctly formatted reports
- [ ] Shareable links work across browsers
- [ ] Scheduled reports deliver on time
- [ ] All features pass accessibility audit

### Phase 2 Completion Criteria
- [ ] Grafana dashboards show real-time data
- [ ] Alerts trigger correctly for defined conditions
- [ ] Metabase questions return accurate results
- [ ] Looker Studio reports refresh automatically
- [ ] All tools accessible via SSO (if configured)

### Overall Success Metrics (3 months post-launch)
- [ ] 80% of executives access reports weekly
- [ ] < 15 min mean time to alert acknowledgment
- [ ] 50+ self-service queries per week in Metabase
- [ ] 90% report delivery success rate
- [ ] Net Promoter Score > 40 from users

---

## Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Performance degradation with new views | High | Medium | Use materialized views, optimize queries |
| Tool sprawl/confusion | Medium | Medium | Clear documentation, training |
| Security misconfiguration | High | Low | Security review, penetration testing |
| Maintenance overhead | Medium | High | Automation, infrastructure as code |
| User adoption | High | Medium | Training, feedback loops, iteration |

---

## Appendix

### A. File Structure Changes

```
monitor-legislativo-v4/
├── R/
│   ├── ui/
│   │   ├── executive_summary_ui.R      # NEW
│   │   └── schedule_config_ui.R        # NEW
│   ├── modules/
│   │   ├── executive_summary_server.R  # NEW
│   │   ├── report_sharing_module.R     # NEW
│   │   └── schedule_module.R           # NEW
│   ├── utils/
│   │   ├── kpi_calculations.R          # NEW
│   │   ├── pdf_generator.R             # NEW
│   │   ├── html_report.R               # NEW
│   │   ├── cloud_storage.R             # NEW
│   │   └── email_sender.R              # NEW
│   └── components/
│       └── sparklines.R                # NEW
├── inst/
│   ├── www/css/
│   │   ├── executive.css               # NEW
│   │   └── print.css                   # NEW
│   └── templates/
│       ├── executive_report.Rmd        # NEW
│       └── state_report.Rmd            # NEW
├── database/
│   └── views/
│       └── mv_executive.sql            # NEW
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── postgresql.yml          # NEW
│   │   └── alerting/
│   │       └── rules.yml               # NEW
│   └── dashboards/
│       ├── system_health.json          # NEW
│       └── pipeline_status.json        # NEW
├── docker-compose.grafana.yml          # NEW
├── docker-compose.metabase.yml         # NEW
├── .github/workflows/
│   └── scheduled_reports.yml           # NEW
└── docs/
    ├── prd/
    │   └── PRD-BI-ENHANCEMENTS.md      # THIS FILE
    └── guides/
        ├── executive_guide.md          # NEW
        └── bi_admin_guide.md           # NEW
```

### B. Technology Comparison Matrix

| Feature | Shiny Enhanced | Grafana | Metabase | Looker Studio |
|---------|---------------|---------|----------|---------------|
| Real-time monitoring | Limited | Excellent | Good | Poor |
| Ad-hoc SQL queries | No | Limited | Excellent | Good |
| Executive reports | Good | Poor | Good | Excellent |
| Sharing with externals | Medium | Poor | Good | Excellent |
| Alerting | No | Excellent | Limited | No |
| Cost | Free | Free | Free | Free |
| Setup complexity | Low | Medium | Low | Low |
| Maintenance | Low | Medium | Low | None (SaaS) |

### C. Reference Links

- [Grafana Documentation](https://grafana.com/docs/)
- [Metabase Documentation](https://www.metabase.com/docs/)
- [Looker Studio Help](https://support.google.com/looker-studio/)
- [Shiny Dashboard Guide](https://rstudio.github.io/shinydashboard/)
- [Quarto Dashboards](https://quarto.org/docs/dashboards/)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-25 | Claude AI | Initial draft |

---

**Next Steps:**
1. Review and approve this PRD
2. Prioritize features for MVP
3. Begin Phase 1, Week 1 implementation
