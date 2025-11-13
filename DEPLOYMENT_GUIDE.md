# Production Deployment Guide
## Monitor Legislativo v4 - Advanced Analytics

**Last Updated**: November 13, 2025
**Version**: Sprint 1 & 2 Complete (6 features)

---

## 📋 **Pre-Deployment Checklist**

### **1. Code & Database** ✅
- [x] All code committed and pushed to GitHub
- [x] Database migrations executed (011, 012, 013)
- [x] Materialized views created (9 views)
- [x] Indexes created (40+ indexes)

### **2. Docker Images**
- [x] Dockerfile.base updated with new packages
- [ ] Base image rebuilt (⏳ **RUNNING NOW** - ~25-30 min)
- [ ] Application image built with new base
- [ ] Images tagged and pushed to registry

### **3. Batch Processing**
- [ ] Readability scores calculated (118,920 docs, ~90-120 min)
- [ ] LSH signatures generated (118,920 docs, ~60 min)
- [ ] Materialized views refreshed

### **4. Testing**
- [ ] Local testing completed
- [ ] All 9 tabs load without errors
- [ ] Database connections work
- [ ] Sample queries return data
- [ ] Export functions work

---

## 🚀 **Deployment Steps**

### **STEP 1: Rebuild Docker Base Image** ⏳ IN PROGRESS

**Command**:
```bash
gcloud builds submit . \
  --config=cloudbuild-build-base.yaml \
  --project=mackmonitor \
  --region=southamerica-east1
```

**Expected Duration**: 25-30 minutes

**New Packages Being Installed**:
- `igraph` - Network analysis
- `visNetwork` - Interactive network visualizations
- `tidygraph`, `ggraph` - Network data structures
- `textreuse` - LSH text similarity
- `forecast`, `changepoint` - Time series anomaly detection

**Status**:
- Started: 2025-11-13 22:14 UTC
- Expected completion: 2025-11-13 22:40 UTC
- Monitor: Check Cloud Build console

---

### **STEP 2: Run Batch Readability Calculation**

**Purpose**: Calculate Flesch-Kincaid, FOG, and SMOG scores for all 118,920 documents

**Command**:
```bash
gcloud builds submit \
  --config=cloudbuild-calculate-readability.yaml \
  --project=mackmonitor \
  --region=southamerica-east1
```

**Configuration**:
- Machine type: E2_HIGHCPU_8
- Timeout: 7200s (2 hours)
- Batch size: 500 documents
- Expected speed: ~20-30 docs/second

**Expected Duration**: 90-120 minutes

**Verification**:
```sql
-- Check progress
SELECT
  COUNT(*) as total_docs,
  COUNT(flesch_kincaid_score) as scored_docs,
  ROUND(100.0 * COUNT(flesch_kincaid_score) / COUNT(*), 2) as pct_complete
FROM documents
WHERE texto_completo IS NOT NULL;

-- View sample scores
SELECT titulo, flesch_kincaid_score, fog_index, smog_index
FROM documents
WHERE flesch_kincaid_score IS NOT NULL
LIMIT 10;
```

---

### **STEP 3: Run LSH Indexing**

**Purpose**: Generate MinHash signatures for text reuse detection

**Command** (after base image is ready):
```bash
# Using Cloud Build
cat > cloudbuild-run-lsh-indexing.yaml << 'EOF'
steps:
  - name: 'gcr.io/mackmonitor/monitor-legislativo-base:latest'
    entrypoint: 'Rscript'
    args: ['R/analytics/batch_lsh_indexing.R', 'full']
    timeout: 3600s
options:
  machineType: 'E2_HIGHCPU_8'
  logging: CLOUD_LOGGING_ONLY
timeout: 3600s
EOF

gcloud builds submit \
  --config=cloudbuild-run-lsh-indexing.yaml \
  --project=mackmonitor \
  --region=southamerica-east1
```

**Expected Duration**: 60 minutes

**Verification**:
```sql
-- Check LSH indexing progress
SELECT COUNT(*) as total_signatures
FROM text_reuse_signatures;

SELECT COUNT(*) as total_buckets
FROM lsh_buckets;

-- Should have ~118k signatures, ~2.3M bucket entries
```

---

### **STEP 4: Build Application Image**

**Command**:
```bash
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --project=mackmonitor \
  --region=southamerica-east1
```

**What This Does**:
- Uses the newly built base image
- Copies application code
- Sets up file structure
- Tags as: `gcr.io/mackmonitor/monitor-legislativo-v4:latest`

**Expected Duration**: 2-3 minutes (fast because base image is cached)

---

### **STEP 5: Deploy to Cloud Run**

**Command**:
```bash
gcloud run deploy monitor-legislativo-v4 \
  --image gcr.io/mackmonitor/monitor-legislativo-v4:latest \
  --platform managed \
  --region southamerica-east1 \
  --allow-unauthenticated \
  --set-env-vars "PGHOST=/cloudsql/mackmonitor:southamerica-east1:mackmonitor-db" \
  --set-env-vars "PGDATABASE=monitor_legislativo" \
  --set-env-vars "PGUSER=monitor_user" \
  --set-secrets "PGPASSWORD=database-password:latest" \
  --add-cloudsql-instances mackmonitor:southamerica-east1:mackmonitor-db \
  --memory 4Gi \
  --cpu 2 \
  --timeout 300 \
  --concurrency 80 \
  --min-instances 0 \
  --max-instances 10
```

**Expected Duration**: 2-3 minutes

**Result**:
- Service URL will be displayed
- Example: `https://monitor-legislativo-v4-xxxxx-uc.a.run.app`

---

### **STEP 6: Post-Deployment Verification**

#### **6.1 Check Service Health**
```bash
# Get service URL
SERVICE_URL=$(gcloud run services describe monitor-legislativo-v4 \
  --region=southamerica-east1 \
  --format='value(status.url)')

# Test homepage loads
curl -I $SERVICE_URL

# Should return HTTP 200
```

#### **6.2 Verify All Tabs Load**

Open in browser and check each tab:
- [ ] Home - Executive summary loads
- [ ] Library - Document search works
- [ ] Geographic - Maps display
  - [ ] Mapa Principal
  - [ ] Corredores de Transporte
  - [ ] Mapa por Estado
- [ ] Analytics - Charts display
  - [ ] Básico
  - [ ] Avançado
- [ ] **NEW: Legibilidade** - Readability dashboard
- [ ] **NEW: Comparação Jurisdicional** - Jurisdictional comparison
- [ ] **NEW: Reuso de Texto** - Text reuse detection
- [ ] **NEW: Análise de Redes** - Network backbone
- [ ] **NEW: Padrões de Emendas** - Amendment patterns
- [ ] **NEW: Detecção de Anomalias** - Anomaly detection

#### **6.3 Test Database Connectivity**

Each new tab should:
- Load without errors
- Display value boxes with real data
- Show visualizations with data
- Allow filtering and interaction
- Support CSV export

#### **6.4 Check Logs**

```bash
# View recent logs
gcloud run services logs read monitor-legislativo-v4 \
  --region=southamerica-east1 \
  --limit=50

# Look for:
# ✅ "Readability Analytics Module loaded"
# ✅ "Multi-Jurisdictional Comparison Module loaded"
# ✅ "Text Reuse Detection Module loaded"
# ✅ "Network Backbone Module loaded"
# ✅ "Amendment Pattern Analysis Module loaded"
# ✅ "Anomaly Detection Module loaded"
```

---

## 🧪 **Testing Procedures**

### **Test 1: Readability Metrics**
1. Navigate to "Legibilidade" tab
2. Verify value boxes show:
   - Average Flesch-Kincaid score (~40-50 expected)
   - Average FOG Index (~12-15 expected)
   - Average SMOG Index (~12-14 expected)
   - Total documents analyzed
3. Check histogram displays distribution
4. Verify filters work (year, document type, level)
5. Test CSV export

### **Test 2: Multi-Jurisdictional Comparison**
1. Navigate to "Comparação Jurisdicional" tab
2. Select "All Jurisdictions" mode
3. Verify bar chart shows Federal/Estadual/Municipal comparison
4. Switch to "State-to-State" mode
5. Select SP, RJ, MG
6. Verify comparison table displays
7. Check heatmap renders
8. Test clustering dendrogram

### **Test 3: Text Reuse Detection**
1. Navigate to "Reuso de Texto" tab
2. Enter a document ID in search
3. Verify similar documents are found (if LSH indexing complete)
4. Check network visualization displays
5. Test cluster view
6. Verify cross-jurisdiction view shows data

### **Test 4: Network Backbone**
1. Navigate to "Análise de Redes" tab
2. Select network type (Citation/Co-authorship/Topic)
3. Adjust backbone parameters (alpha threshold)
4. Verify network visualization loads
5. Check community detection results
6. Test GEXF export

### **Test 5: Amendment Patterns**
1. Navigate to "Padrões de Emendas" tab
2. Verify timeline view displays
3. Check hotspots table shows most amended laws
4. Verify cascade network visualization
5. Test cross-jurisdiction flow diagram
6. Check velocity metrics chart

### **Test 6: Anomaly Detection**
1. Navigate to "Detecção de Anomalias" tab
2. Select anomaly type (Volume/Text/Temporal)
3. Adjust sensitivity threshold
4. Verify anomaly scatter plot displays
5. Check anomaly table shows detected outliers
6. Verify severity scores are calculated
7. Test multiple detection methods

---

## 📊 **Expected Performance Metrics**

### **Query Performance** (with indexes)
- Readability queries: < 500ms
- Jurisdictional comparison: < 1s
- Text reuse similarity search: < 500ms
- Network construction: < 5s for 10k nodes
- Amendment detection: < 1s
- Anomaly detection: < 2s

### **Page Load Times**
- Homepage: < 2s
- Analytics tabs: 2-4s initial load
- Visualizations: < 2s render time
- Filtering: < 1s response

### **Resource Usage**
- Memory: 2-3 GB typical, 4 GB max
- CPU: 20-40% typical, 80% during queries
- Concurrent users: 50-100 supported
- Cold start: 10-15s

---

## 🔧 **Troubleshooting**

### **Issue: Base Image Build Fails**

**Symptoms**: Cloud Build error during R package installation

**Solutions**:
1. Check package names are correct
2. Increase timeout in cloudbuild-build-base.yaml
3. Check CRAN availability
4. Try alternative package repository

```yaml
# Increase timeout if needed
timeout: 2400s  # 40 minutes instead of 30
```

### **Issue: Batch Jobs Timeout**

**Symptoms**: Readability or LSH job exceeds 2-hour limit

**Solutions**:
1. Increase machine size to E2_HIGHCPU_16
2. Increase timeout to 3600s
3. Reduce batch size to process fewer docs at once
4. Resume from checkpoint if script supports it

### **Issue: Application Won't Start**

**Symptoms**: Cloud Run deployment fails or crashes immediately

**Solutions**:
1. Check logs: `gcloud run services logs read`
2. Verify database connection settings
3. Check all modules loaded successfully
4. Verify base image has all packages
5. Test locally first with Docker

```bash
# Run locally
docker run -p 8080:8080 \
  -e PGHOST=localhost \
  -e PGDATABASE=monitor_legislativo \
  -e PGUSER=monitor_user \
  -e PGPASSWORD=yourpassword \
  gcr.io/mackmonitor/monitor-legislativo-v4:latest
```

### **Issue: New Tabs Don't Load**

**Symptoms**: Error messages in specific analytics tabs

**Solutions**:
1. Check module files exist in container
2. Verify database tables/views exist
3. Check for R package installation errors
4. Review startup logs for module loading errors
5. Test module functions in R console

```r
# Test module loading
source("R/analytics/readability_metrics.R")
source("modules/analytics/readability_ui.R")
source("modules/analytics/readability_server.R")

# Should load without errors
```

### **Issue: Queries Are Slow**

**Symptoms**: Tabs take >5s to load data

**Solutions**:
1. Verify indexes were created:
   ```sql
   SELECT schemaname, tablename, indexname
   FROM pg_indexes
   WHERE tablename = 'documents';
   ```

2. Refresh materialized views:
   ```sql
   REFRESH MATERIALIZED VIEW CONCURRENTLY readability_summary;
   REFRESH MATERIALIZED VIEW CONCURRENTLY jurisdictional_summary;
   REFRESH MATERIALIZED VIEW CONCURRENTLY state_level_summary;
   REFRESH MATERIALIZED VIEW CONCURRENTLY jurisdiction_level_summary;
   REFRESH MATERIALIZED VIEW CONCURRENTLY temporal_trends_summary;
   ```

3. Analyze tables:
   ```sql
   ANALYZE documents;
   ANALYZE text_reuse_signatures;
   ANALYZE network_edges;
   ```

---

## 📅 **Maintenance Schedule**

### **Daily**
- Monitor Cloud Run logs for errors
- Check service health endpoint
- Review anomaly detection alerts

### **Weekly**
- Refresh materialized views
- Review performance metrics
- Check disk usage

```bash
# Weekly materialized view refresh (cron job)
0 2 * * 0 psql -c "REFRESH MATERIALIZED VIEW CONCURRENTLY readability_summary;"
0 3 * * 0 psql -c "REFRESH MATERIALIZED VIEW CONCURRENTLY jurisdictional_summary;"
```

### **Monthly**
- Review and optimize slow queries
- Archive old logs
- Update base image if needed
- Re-index text reuse if corpus grows >10%

### **Quarterly**
- Full system performance audit
- Security updates
- Feature usage analysis
- User feedback review

---

## 🔐 **Security Checklist**

- [x] Database password in Secret Manager
- [x] Cloud SQL private IP connection
- [x] Service account with minimal permissions
- [ ] Enable Cloud Armor (DDoS protection)
- [ ] Set up VPC Service Controls
- [ ] Configure audit logging
- [ ] Implement rate limiting
- [ ] Add authentication (if required)

---

## 📈 **Monitoring & Alerts**

### **Key Metrics to Monitor**

1. **Service Health**
   - Uptime percentage
   - Request latency (p50, p95, p99)
   - Error rate
   - Container instance count

2. **Database Performance**
   - Connection pool usage
   - Query execution time
   - Active connections
   - Deadlocks

3. **User Engagement**
   - Active users
   - Tab usage (which features are most used)
   - Export frequency
   - Session duration

### **Recommended Alerts**

```yaml
# Cloud Monitoring Alert Policy
- name: High Error Rate
  condition: error_rate > 5%
  duration: 5 minutes
  notification: email, slack

- name: High Latency
  condition: p95_latency > 10s
  duration: 3 minutes
  notification: email

- name: Database Connection Errors
  condition: db_connection_errors > 10
  duration: 1 minute
  notification: pagerduty
```

---

## 🎯 **Success Criteria**

### **Deployment is Successful When**:
- ✅ All 9 analytics tabs load without errors
- ✅ Database queries return data in < 5s
- ✅ No startup errors in logs
- ✅ All 6 new features functional
- ✅ Export functions work
- ✅ Visualizations render correctly
- ✅ Filters apply properly
- ✅ Service handles 50+ concurrent users

### **Rollback If**:
- ❌ Critical errors on startup
- ❌ Database connection fails
- ❌ More than 2 features broken
- ❌ Error rate > 10%
- ❌ Cannot handle typical user load

---

## 🔄 **Rollback Procedure**

If deployment fails:

```bash
# 1. Revert to previous version
gcloud run services update monitor-legislativo-v4 \
  --image gcr.io/mackmonitor/monitor-legislativo-v4:PREVIOUS_TAG \
  --region southamerica-east1

# 2. Check previous successful build
gcloud builds list --limit=10

# 3. Redeploy previous image
gcloud run deploy monitor-legislativo-v4 \
  --image gcr.io/mackmonitor/monitor-legislativo-v4@sha256:PREVIOUS_DIGEST \
  --region southamerica-east1

# 4. Verify rollback successful
curl -I https://monitor-legislativo-v4-xxxxx-uc.a.run.app
```

---

## 📞 **Support Contacts**

- **Technical Issues**: Check SESSION_SUMMARY.md, ADVANCED_ANALYTICS_IMPLEMENTATION_STATUS.md
- **Feature Documentation**: See docs/ directory and individual module READMEs
- **Database Issues**: Review migration scripts in database/migrations/
- **Performance Issues**: Check DEPLOYMENT_GUIDE.md troubleshooting section

---

## ✅ **Final Pre-Launch Checklist**

Before going live:
- [ ] All batch jobs completed successfully
- [ ] Base image rebuilt and tested
- [ ] Application image built
- [ ] Deployed to staging environment
- [ ] All 9 tabs tested manually
- [ ] Performance tests passed
- [ ] Security review completed
- [ ] Monitoring and alerts configured
- [ ] Documentation reviewed
- [ ] Rollback procedure tested
- [ ] Team trained on new features
- [ ] Users notified of new capabilities

---

**Document Version**: 1.0
**Last Updated**: November 13, 2025
**Next Review**: After successful deployment
**Status**: Ready for deployment pending batch job completion

---

*Monitor Legislativo v4 - Production Deployment Guide*
*Advanced Analytics - Sprint 1 & 2*
