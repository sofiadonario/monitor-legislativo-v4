# BI Hybrid Architecture - Zero Cost Implementation
**Monitor Legislativo v4 - Business Intelligence Enhancement**

**Version:** 1.0
**Date:** 2025-11-25
**Target Cost:** $0 additional monthly spend
**Timeline:** 4-6 weeks implementation

---

## Executive Summary

This architecture delivers the full BI capability stack (executive dashboards, real-time monitoring, self-service analytics, and shareable reports) while maintaining the current ~$7-10/month GCP budget by leveraging:

1. **GCP Free Tier** services (Cloud Run, Storage, Scheduler)
2. **Free SaaS BI Tools** (Grafana Cloud, Metabase Cloud, Looker Studio)
3. **Existing Infrastructure** (Cloud SQL, Cloud Run containers)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          GOOGLE CLOUD PLATFORM                              │
│                        (Current: $7-10/month)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    CLOUD RUN SERVICE                               │    │
│  │                   monitor-legislativo-v4                           │    │
│  │                                                                    │    │
│  │  ┌──────────────────────────────────────────────────────────┐     │    │
│  │  │         Enhanced R/Shiny Application                     │     │    │
│  │  │  ┌────────────────┐  ┌────────────────┐                 │     │    │
│  │  │  │   Executive    │  │   Enhanced     │                 │     │    │
│  │  │  │   Dashboard    │  │   Analytics    │                 │     │    │
│  │  │  │   Module       │  │   Views        │                 │     │    │
│  │  │  └────────────────┘  └────────────────┘                 │     │    │
│  │  │  ┌────────────────┐  ┌────────────────┐                 │     │    │
│  │  │  │   PDF Export   │  │   Report       │                 │     │    │
│  │  │  │   Generator    │  │   Scheduler    │                 │     │    │
│  │  │  └────────────────┘  └────────────────┘                 │     │    │
│  │  └──────────────────────────────────────────────────────────┘     │    │
│  └────────────────┬───────────────────────────────────────────────────┘    │
│                   │                                                         │
│  ┌────────────────┴────────────┐                                           │
│  │    CLOUD SQL (PostgreSQL)   │                                           │
│  │      mackmonitor-db         │                                           │
│  │  ┌──────────────────────┐   │                                           │
│  │  │  Legislative Data    │   │◄──────────────┐                          │
│  │  │  134,000+ documents  │   │               │                          │
│  │  └──────────────────────┘   │               │                          │
│  │  ┌──────────────────────┐   │               │                          │
│  │  │  Materialized Views  │   │               │                          │
│  │  │  - Executive KPIs    │   │               │                          │
│  │  │  - Analytics Summary │   │               │                          │
│  │  └──────────────────────┘   │               │                          │
│  └─────────────┬───────────────┘               │                          │
│                │                                │                          │
│  ┌─────────────┴───────────────┐               │                          │
│  │   CLOUD STORAGE (FREE)      │               │                          │
│  │   - PDF Reports             │               │                          │
│  │   - Shareable Links         │               │                          │
│  │   - 5GB FREE tier           │               │                          │
│  └─────────────────────────────┘               │                          │
│                                                 │                          │
│  ┌─────────────────────────────┐               │                          │
│  │  CLOUD SCHEDULER (FREE)     │               │                          │
│  │  - Daily report generation  │               │                          │
│  │  - Weekly email delivery    │               │                          │
│  │  - 3 jobs FREE              │               │                          │
│  └─────────────────────────────┘               │                          │
│                                                 │                          │
└─────────────────────────────────────────────────┼──────────────────────────┘
                                                  │
                   ┌──────────────────────────────┼──────────────────────────┐
                   │              FREE SAAS BI TOOLS LAYER                   │
                   ├──────────────────────────────┴──────────────────────────┤
                   │                                                          │
┌──────────────────┴───────────────┐  ┌──────────────────────────────────┐  │
│    GRAFANA CLOUD (FREE)          │  │   METABASE CLOUD (FREE)          │  │
│    grafana.com                   │  │   metabase.com                   │  │
│                                  │  │                                  │  │
│  ┌────────────────────────────┐  │  │  ┌────────────────────────────┐  │  │
│  │ Real-Time Monitoring       │  │  │  │ Self-Service SQL          │  │  │
│  │ - System Health            │  │  │  │ - Ad-hoc Queries          │  │  │
│  │ - Data Pipeline Status     │  │  │  │ - Saved Questions         │  │  │
│  │ - Application Metrics      │  │  │  │ - Custom Dashboards       │  │  │
│  └────────────────────────────┘  │  │  └────────────────────────────┘  │  │
│  ┌────────────────────────────┐  │  │  ┌────────────────────────────┐  │  │
│  │ Alerting                   │  │  │  │ User Management           │  │  │
│  │ - Email notifications      │  │  │  │ - 2 users (FREE tier)     │  │  │
│  │ - Custom alert rules       │  │  │  │ - Read-only DB access     │  │  │
│  └────────────────────────────┘  │  │  └────────────────────────────┘  │  │
│                                  │  │                                  │  │
│  PostgreSQL Connection:          │  │  PostgreSQL Connection:          │  │
│  - Public IP via Cloud SQL       │  │  - Public IP via Cloud SQL       │  │
│  - Read-only user                │  │  - Read-only user                │  │
│  - 14-day metric retention       │  │  - Community support             │  │
└──────────────────────────────────┘  └──────────────────────────────────┘  │
                                                                             │
┌─────────────────────────────────────────────────────────────────────────┐  │
│                  LOOKER STUDIO (FREE - Google Native)                   │  │
│                  lookerstudio.google.com                                │  │
│                                                                         │  │
│  ┌────────────────────────────────────────────────────────────────┐    │  │
│  │ Executive Reports & Sharing                                    │    │  │
│  │ ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │    │  │
│  │ │ Monthly Summary  │  │ State Analysis   │  │ Trend Report │  │    │  │
│  │ │ - KPI Dashboard  │  │ - Geographic viz │  │ - Time series│  │    │  │
│  │ │ - Growth metrics │  │ - Comparisons    │  │ - Forecasts  │  │    │  │
│  │ └──────────────────┘  └──────────────────┘  └──────────────┘  │    │  │
│  │                                                                │    │  │
│  │ Data Source: Cloud SQL (via Google connector)                 │    │  │
│  │ Sharing: Public links, embedded iframes, scheduled PDFs        │    │  │
│  └────────────────────────────────────────────────────────────────┘    │  │
└─────────────────────────────────────────────────────────────────────────┘  │
                                                                             │
┌─────────────────────────────────────────────────────────────────────────┐  │
│                    EMAIL DELIVERY (FREE)                                │  │
│                    resend.com                                           │  │
│                                                                         │  │
│  - 3,000 emails/month FREE                                              │  │
│  - Scheduled reports via Cloud Scheduler                                │  │
│  - Professional sender domain                                           │  │
└─────────────────────────────────────────────────────────────────────────┘  │
                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. GCP Components (Current Infrastructure)

#### Cloud Run Service
**Container:** monitor-legislativo-v4
**Current:** Shiny application
**Enhancement:** Add executive dashboard module

**Configuration:**
```yaml
# cloudbuild.yaml (existing)
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/monitor-legislativo-v4', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/monitor-legislativo-v4']
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
      - 'run'
      - 'deploy'
      - 'monitor-legislativo-v4'
      - '--image=gcr.io/$PROJECT_ID/monitor-legislativo-v4'
      - '--region=southamerica-east1'
      - '--platform=managed'
      - '--allow-unauthenticated'
```

**Cost:** $0 extra (within free tier: 2M requests/month)

---

#### Cloud SQL PostgreSQL
**Instance:** mackmonitor-db
**Current:** lexml_db database
**Enhancement:** Add materialized views for BI

**New Database Objects:**
```sql
-- Materialized view for executive KPIs
CREATE MATERIALIZED VIEW mv_executive_kpis AS
SELECT
  COUNT(*) as total_documents,
  COUNT(DISTINCT state) as states_covered,
  COUNT(CASE WHEN date_published >= CURRENT_DATE - 30 THEN 1 END) as docs_last_30_days,
  MAX(date_published) as latest_document_date
FROM documents;

-- Refresh schedule (via Cloud Scheduler)
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_executive_kpis;
```

**Read-Only User for BI Tools:**
```sql
-- Create read-only user for external BI tools
CREATE USER bi_readonly WITH PASSWORD 'secure_random_password';
GRANT CONNECT ON DATABASE lexml_db TO bi_readonly;
GRANT USAGE ON SCHEMA public TO bi_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO bi_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO bi_readonly;
```

**Cost:** $0 extra (same instance)

---

#### Cloud Storage
**Bucket:** monitor-legislativo-reports
**Purpose:** Store generated PDF reports

**Configuration:**
```bash
# Create bucket
gsutil mb -c STANDARD -l southamerica-east1 gs://monitor-legislativo-reports

# Set lifecycle policy (auto-delete after 90 days)
cat > lifecycle.json <<EOF
{
  "lifecycle": {
    "rule": [{
      "action": {"type": "Delete"},
      "condition": {"age": 90}
    }]
  }
}
EOF
gsutil lifecycle set lifecycle.json gs://monitor-legislativo-reports

# Enable public read for shareable links
gsutil iam ch allUsers:objectViewer gs://monitor-legislativo-reports
```

**Cost:** FREE (5GB/month free tier)

---

#### Cloud Scheduler
**Jobs:** Scheduled report generation

**Configuration:**
```bash
# Daily executive report
gcloud scheduler jobs create http daily-executive-report \
  --location=southamerica-east1 \
  --schedule="0 8 * * *" \
  --uri="https://monitor-legislativo-v4-xxxxx.run.app/api/generate-report" \
  --http-method=POST \
  --oidc-service-account-email="scheduler@mackmonitor.iam.gserviceaccount.com"

# Weekly summary email
gcloud scheduler jobs create http weekly-summary-email \
  --location=southamerica-east1 \
  --schedule="0 9 * * MON" \
  --uri="https://monitor-legislativo-v4-xxxxx.run.app/api/send-weekly-report" \
  --http-method=POST \
  --oidc-service-account-email="scheduler@mackmonitor.iam.gserviceaccount.com"
```

**Cost:** FREE (3 jobs/month free tier)

---

### 2. Free SaaS BI Tools

#### Grafana Cloud (FREE Tier)

**Signup:** https://grafana.com/auth/sign-up/create-user
**Plan:** Free Forever
**Limits:**
- 10,000 series metrics
- 50 GB logs
- 50 GB traces
- 14-day retention

**Setup Steps:**

1. **Create Account & Get Connection String**
```bash
# Grafana Cloud provides a hosted Prometheus/Loki endpoint
# Note your:
# - Prometheus URL: https://prometheus-xxxxx.grafana.net
# - API Key: your_grafana_cloud_api_key
```

2. **Connect to Cloud SQL**
```yaml
# grafana-datasources.yaml (configure in Grafana UI)
apiVersion: 1
datasources:
  - name: Monitor Legislativo PostgreSQL
    type: postgres
    url: 34.39.228.246:5432
    database: lexml_db
    user: bi_readonly
    secureJsonData:
      password: 'secure_password'
    jsonData:
      sslmode: 'require'
      postgresVersion: 1500
```

3. **Import Dashboards**
- System Health Dashboard (monitors Cloud Run metrics)
- Data Pipeline Dashboard (legislative data freshness)
- Application Metrics (user activity, query performance)

**Cost:** $0/month

---

#### Metabase Cloud (FREE Tier)

**Signup:** https://www.metabase.com/start/hosted
**Plan:** Free Starter
**Limits:**
- 2 users
- 5 questions
- Community support

**Setup Steps:**

1. **Create Account**
- Email: your_email@domain.com
- Instance URL: https://mackmonitor.metabaseapp.com

2. **Add Database Connection**
```
Database type: PostgreSQL
Host: 34.39.228.246
Port: 5432
Database name: lexml_db
Username: bi_readonly
Password: [secure_password]
SSL: Yes
```

3. **Create Collections**
```
Monitor Legislativo/
├── Executive Dashboards/
│   ├── Monthly Summary
│   └── State Comparison
└── Research/
    ├── Topic Analysis
    └── Temporal Patterns
```

**Sample Questions:**
```sql
-- Q1: Documents by State (last 30 days)
SELECT state, COUNT(*) as doc_count
FROM documents
WHERE date_published >= CURRENT_DATE - 30
GROUP BY state
ORDER BY doc_count DESC
LIMIT 10;

-- Q2: Legislative Activity Trend
SELECT
  DATE_TRUNC('month', date_published) as month,
  COUNT(*) as documents
FROM documents
WHERE date_published >= CURRENT_DATE - 365
GROUP BY month
ORDER BY month;
```

**Cost:** $0/month

---

#### Looker Studio (FREE - Google Native)

**Access:** https://lookerstudio.google.com
**Plan:** Free (unlimited)

**Setup Steps:**

1. **Connect Cloud SQL**
```
Data Source > Add a connector > PostgreSQL
Host: 34.39.228.246
Port: 5432
Database: lexml_db
Username: bi_readonly
Password: [secure_password]
Enable SSL: Yes
```

2. **Create Report Templates**

**Template 1: Executive Monthly Summary**
- Page 1: KPI Scorecard (4 key metrics)
- Page 2: State Heatmap (geographic distribution)
- Page 3: Document Type Breakdown (pie chart)
- Page 4: 90-Day Trend Line
- Page 5: Top 10 Recent Documents (table)

3. **Sharing Options**
```
Share > Get shareable link
- View access (public or restricted)
- Embed code for iframe
- Schedule email delivery (PDF)
  - Frequency: Weekly/Monthly
  - Recipients: stakeholders@domain.com
```

**Cost:** $0/month

---

#### Resend Email (FREE Tier)

**Signup:** https://resend.com/signup
**Plan:** Free
**Limits:** 3,000 emails/month

**Setup:**

1. **Get API Key**
```bash
# After signup, generate API key
# Store in Cloud Secret Manager
echo -n "re_xxx_your_api_key" | gcloud secrets create resend-api-key --data-file=-
```

2. **Verify Domain** (optional, for professional sender)
```
Domain: monitor-legislativo.com.br
Add DNS TXT records provided by Resend
```

3. **Integration in Shiny App**
```r
# R/utils/email_sender.R
library(httr)

send_report_email <- function(recipient, report_url, report_title) {
  api_key <- Sys.getenv("RESEND_API_KEY")

  response <- POST(
    "https://api.resend.com/emails",
    add_headers(
      "Authorization" = paste("Bearer", api_key),
      "Content-Type" = "application/json"
    ),
    body = toJSON(list(
      from = "reports@monitor-legislativo.com.br",
      to = recipient,
      subject = paste("Monitor Legislativo:", report_title),
      html = paste0(
        "<h2>", report_title, "</h2>",
        "<p>Your report is ready:</p>",
        "<a href='", report_url, "'>View Report</a>"
      )
    ), auto_unbox = TRUE),
    encode = "json"
  )

  return(response)
}
```

**Cost:** $0/month (up to 3,000 emails)

---

## Data Flow

### Report Generation Flow
```
1. Cloud Scheduler triggers → 2. Cloud Run endpoint
   ↓
3. Shiny app queries → 4. Cloud SQL (materialized views)
   ↓
5. Generate PDF → 6. Upload to Cloud Storage
   ↓
7. Create shareable link → 8. Send email via Resend
```

### Real-Time Monitoring Flow
```
1. Grafana Cloud → 2. PostgreSQL read-only connection
   ↓
3. Query metrics → 4. Display dashboards
   ↓
5. Alert rules → 6. Email notifications
```

### Self-Service Analytics Flow
```
1. User accesses Metabase → 2. Browse saved questions
   ↓
3. Run custom SQL → 4. PostgreSQL (read-only)
   ↓
5. Save results → 6. Export CSV/JSON
```

---

## Security Configuration

### Cloud SQL Public IP Access
```bash
# Authorize Grafana Cloud IPs
gcloud sql instances patch mackmonitor-db \
  --authorized-networks=\
35.233.176.0/24,\
35.245.0.0/16,\
34.128.0.0/10

# Enable SSL
gcloud sql ssl-certs create grafana-cert \
  --instance=mackmonitor-db

# Download client cert
gcloud sql ssl-certs describe grafana-cert \
  --instance=mackmonitor-db \
  --format="get(cert)" > client-cert.pem
```

### Cloud Storage Signed URLs
```r
# R/utils/signed_urls.R
library(googleCloudStorageR)

generate_signed_url <- function(object_name, expiration_hours = 72) {
  gcs_signed_url(
    bucket = "monitor-legislativo-reports",
    object = object_name,
    duration = expiration_hours * 3600
  )
}
```

---

## Implementation Timeline

### Week 1: GCP Foundation
- [ ] Create Cloud Storage bucket
- [ ] Set up Cloud Scheduler jobs
- [ ] Create materialized views in Cloud SQL
- [ ] Configure read-only database user
- [ ] Set up Resend email account

### Week 2: Shiny Enhancements
- [ ] Build executive dashboard UI
- [ ] Implement PDF export functionality
- [ ] Create shareable link generator
- [ ] Integrate email delivery
- [ ] Test report generation end-to-end

### Week 3: External BI Tools Setup
- [ ] Sign up for Grafana Cloud
- [ ] Configure PostgreSQL data source in Grafana
- [ ] Create system health dashboards
- [ ] Set up alert rules
- [ ] Sign up for Metabase Cloud
- [ ] Connect Metabase to Cloud SQL
- [ ] Create saved questions library

### Week 4: Looker Studio & Polish
- [ ] Connect Looker Studio to Cloud SQL
- [ ] Build executive report templates
- [ ] Configure scheduled email delivery
- [ ] Test all integrations
- [ ] Document setup procedures
- [ ] Train users

---

## Cost Breakdown (Monthly)

| Service | Tier | Cost |
|---------|------|------|
| **Cloud Run** | Free tier (2M requests) | $0 |
| **Cloud SQL** | db-g1-small | $7-10 (current) |
| **Cloud Storage** | 5GB | $0 (free tier) |
| **Cloud Scheduler** | 3 jobs | $0 (free tier) |
| **Cloud Build** | 120 min/day | $0 (free tier) |
| **Grafana Cloud** | Free plan | $0 |
| **Metabase Cloud** | Free starter | $0 |
| **Looker Studio** | Unlimited | $0 |
| **Resend Email** | 3k emails/month | $0 |
| **TOTAL** | | **$7-10** |

**Additional Cost: $0/month** ✅

---

## Success Metrics

### Technical Metrics
- [ ] Executive dashboard loads < 3 seconds
- [ ] PDF generation completes < 10 seconds
- [ ] Scheduled reports deliver 99% success rate
- [ ] Grafana dashboards update every 1 minute
- [ ] Metabase queries execute < 5 seconds

### Business Metrics
- [ ] 10+ executives access reports weekly
- [ ] 20+ self-service queries per week
- [ ] 50+ report shares per month
- [ ] < 15 min alert response time
- [ ] User satisfaction score > 4/5

---

## Maintenance & Operations

### Daily
- Monitor Cloud Scheduler job success
- Check email delivery logs
- Review Grafana alerts

### Weekly
- Refresh materialized views
- Review Metabase usage analytics
- Clean up old reports (auto-deleted after 90 days)

### Monthly
- Audit database performance
- Review Cloud SQL costs
- Update Looker Studio report templates
- Check free tier usage limits

---

## Troubleshooting

### Common Issues

**Cloud Scheduler job fails:**
```bash
# Check logs
gcloud logging read "resource.type=cloud_scheduler_job" --limit 50

# Test endpoint manually
curl -X POST https://monitor-legislativo-v4-xxxxx.run.app/api/generate-report
```

**Grafana can't connect to Cloud SQL:**
```sql
-- Verify read-only user permissions
SELECT * FROM information_schema.role_table_grants
WHERE grantee = 'bi_readonly';

-- Check authorized networks
gcloud sql instances describe mackmonitor-db --format="get(settings.ipConfiguration.authorizedNetworks)"
```

**Email delivery fails:**
```r
# Check Resend API key
Sys.getenv("RESEND_API_KEY")

# Test email endpoint
send_report_email("test@example.com", "https://test.com", "Test Report")
```

---

## Next Steps

1. **Review this architecture** with stakeholders
2. **Approve implementation** timeline
3. **Assign resources** (developer time)
4. **Begin Week 1** setup tasks
5. **Track progress** against success metrics

---

## Appendix: Environment Variables

```bash
# .env (add to Cloud Run)
RESEND_API_KEY=re_xxx_your_api_key
GCS_BUCKET_NAME=monitor-legislativo-reports
REPORT_BASE_URL=https://storage.googleapis.com/monitor-legislativo-reports
DB_READONLY_USER=bi_readonly
DB_READONLY_PASSWORD=secure_random_password
GRAFANA_API_KEY=your_grafana_cloud_api_key
```

Store securely in **Cloud Secret Manager**:
```bash
echo -n "re_xxx" | gcloud secrets create resend-api-key --data-file=-
echo -n "secure_password" | gcloud secrets create db-readonly-password --data-file=-
```

---

**Document Version:** 1.0
**Last Updated:** 2025-11-25
**Status:** Ready for Implementation
