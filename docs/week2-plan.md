# Week 2 Implementation Plan: Report Generation & Export
**Monitor Legislativo v4 - BI Enhancements Phase 1**

**Start Date:** 2025-11-26 (estimated)
**Target Completion:** Week of 2025-12-09
**Budget Impact:** $0 additional cost
**Status:** 🟡 Planning

---

## Overview

Week 2 builds on Week 1's infrastructure foundation to deliver executable report generation capabilities. With materialized views, Cloud Storage, and database access configured, we can now implement the UI and export functionality that transforms raw data into shareable executive reports.

**Key Deliverables:**
- Executive dashboard UI in Shiny app
- PDF report generation using pagedown
- HTML static report generator
- Print-optimized CSS for professional output
- Report export functionality integrated into app

---

## Prerequisites from Week 1 ✅

All required infrastructure is in place:
- ✅ Cloud Storage bucket: `gs://monitor-legislativo-reports`
- ✅ Materialized views: `mv_executive_kpis`, `mv_state_summary`, `mv_monthly_trends`
- ✅ Read-only database user: `bi_readonly`
- ✅ SSL certificates for secure database access
- ✅ Service account with Cloud Run invoker permissions

---

## Week 2 Tasks Checklist

### Task 2.1: Executive Dashboard UI Module
**Objective:** Create polished executive-focused UI within Shiny app
**Estimated Time:** 4 hours
**Cost Impact:** $0

#### Requirements
- One-page executive summary with KPIs
- Load time < 3 seconds using materialized views
- Trend sparklines for 30/60/90 day periods
- Top 5 most active states visualization
- Recent legislative highlights (last 7 days)
- Responsive layout that looks good in PDF export

#### Files to Create/Modify
```
R/
├── ui/
│   └── executive_summary_ui.R      (NEW) - UI layout
├── modules/
│   └── executive_summary_server.R  (NEW) - Server logic
└── utils/
    └── kpi_calculations.R          (NEW) - KPI computation

inst/www/css/
└── executive.css                   (NEW) - Executive styling
```

#### Implementation Steps
- [ ] Create executive summary UI layout with value boxes
- [ ] Connect UI to materialized views (mv_executive_kpis, mv_state_summary, mv_monthly_trends)
- [ ] Implement KPI calculation functions
- [ ] Build sparkline components for trend visualization
- [ ] Create top states horizontal bar chart
- [ ] Add recent highlights card layout
- [ ] Style with executive-focused CSS
- [ ] Add executive tab to main navigation in app_phoenix.R
- [ ] Test load time < 3 seconds

#### Success Criteria
- ✅ Executive dashboard loads in < 3 seconds
- ✅ All KPIs display correctly from materialized views
- ✅ Sparklines show 30/60/90 day trends
- ✅ Top 5 states visualization accurate
- ✅ Layout is responsive and print-friendly

---

### Task 2.2: PDF Export Functionality
**Objective:** Generate professional PDF reports using pagedown
**Estimated Time:** 3 hours
**Cost Impact:** $0

#### Requirements
- PDF export using pagedown/chrome_print
- A4/Letter format with proper margins
- Branded header with logo
- Footer with page numbers and generation timestamp
- Export button in UI
- PDF saved to Cloud Storage bucket

#### Files to Create
```
R/
├── utils/
│   └── pdf_generator.R             (NEW) - PDF generation logic
└── modules/
    └── export_module.R             (NEW) - Export button module

inst/
├── templates/
│   └── executive_report.Rmd        (NEW) - RMarkdown template
└── www/
    └── css/
        └── print.css               (NEW) - Print-optimized CSS
```

#### Implementation Steps
- [ ] Install pagedown package (already in renv)
- [ ] Create RMarkdown template for executive report
- [ ] Implement PDF generation function using chrome_print()
- [ ] Add branded header/footer to template
- [ ] Create print-optimized CSS
- [ ] Build export button module
- [ ] Upload generated PDF to Cloud Storage
- [ ] Generate signed URL for download
- [ ] Add export button to executive dashboard
- [ ] Test PDF output quality

#### Success Criteria
- ✅ PDF generates in < 10 seconds
- ✅ PDF uploaded to Cloud Storage successfully
- ✅ Signed URL works and expires after 72 hours
- ✅ PDF is professional-quality and print-ready
- ✅ Page breaks work correctly

---

### Task 2.3: HTML Static Report Generator
**Objective:** Generate standalone HTML reports for sharing
**Estimated Time:** 2 hours
**Cost Impact:** $0

#### Requirements
- Self-contained HTML file (embedded CSS/JS)
- No dependencies on external resources
- Responsive design
- Unique filename with timestamp
- Upload to Cloud Storage
- Shareable via signed URL

#### Files to Create
```
R/
└── utils/
    └── html_report_generator.R     (NEW) - HTML generation
```

#### Implementation Steps
- [ ] Create HTML report template
- [ ] Implement data injection into HTML
- [ ] Embed all CSS inline (no external deps)
- [ ] Add timestamp and metadata to report
- [ ] Generate unique filename
- [ ] Upload HTML to Cloud Storage
- [ ] Create signed URL for sharing
- [ ] Add HTML export option to UI
- [ ] Test HTML in different browsers

#### Success Criteria
- ✅ HTML report is fully self-contained
- ✅ No external dependencies required
- ✅ Works offline once downloaded
- ✅ Responsive on mobile/tablet/desktop
- ✅ Uploaded to Cloud Storage with signed URL

---

### Task 2.4: Cloud Storage Integration
**Objective:** Seamless upload/download with GCS bucket
**Estimated Time:** 2 hours
**Cost Impact:** $0

#### Requirements
- Upload PDFs and HTML to gs://monitor-legislativo-reports
- Generate signed URLs with 72-hour expiration
- Handle upload errors gracefully
- Track uploaded files in database (optional)
- Clean up old files (handled by lifecycle policy)

#### Files to Create
```
R/
└── utils/
    └── cloud_storage.R             (NEW) - GCS integration
```

#### Implementation Steps
- [ ] Install googleCloudStorageR package
- [ ] Authenticate with Cloud Storage using service account
- [ ] Create upload function for PDFs/HTML
- [ ] Implement signed URL generation (72-hour expiration)
- [ ] Add error handling for upload failures
- [ ] Create download function for testing
- [ ] Test upload/download cycle
- [ ] Verify lifecycle policy auto-deletes old files

#### Success Criteria
- ✅ Files upload successfully to bucket
- ✅ Signed URLs work and expire after 72 hours
- ✅ Upload errors handled gracefully
- ✅ Old files auto-delete after 90 days (lifecycle policy)

---

### Task 2.5: Export Button Integration
**Objective:** Add export controls to executive dashboard
**Estimated Time:** 1.5 hours
**Cost Impact:** $0

#### Requirements
- "Export PDF" button in dashboard
- "Export HTML" button in dashboard
- "Copy Link" button for shareable URL
- Progress indicator during generation
- Success/error notifications
- Download link after generation

#### Files to Modify
```
R/
├── ui/
│   └── executive_summary_ui.R      (MODIFY) - Add export buttons
└── modules/
    └── executive_summary_server.R  (MODIFY) - Connect to export logic
```

#### Implementation Steps
- [ ] Add export button group to UI
- [ ] Style buttons to match executive theme
- [ ] Connect buttons to export modules
- [ ] Show progress spinner during generation
- [ ] Display success notification with download link
- [ ] Show error notification on failure
- [ ] Add "Copy Link" functionality
- [ ] Test user flow end-to-end

#### Success Criteria
- ✅ Export buttons visible and accessible
- ✅ Progress indicator shows during generation
- ✅ Download link appears on success
- ✅ Copy link functionality works
- ✅ Error handling provides helpful feedback

---

### Task 2.6: Testing & Performance Optimization
**Objective:** Ensure reliability and performance
**Estimated Time:** 2 hours
**Cost Impact:** $0

#### Testing Checklist
- [ ] Test PDF generation with different data volumes
- [ ] Test HTML export with various browsers
- [ ] Verify signed URLs expire correctly
- [ ] Test concurrent exports (multiple users)
- [ ] Verify materialized views update correctly
- [ ] Test export with missing/null data
- [ ] Check memory usage during PDF generation
- [ ] Verify Cloud Storage quota not exceeded

#### Performance Targets
- PDF generation: < 10 seconds
- HTML generation: < 5 seconds
- Cloud Storage upload: < 3 seconds
- Total export time: < 15 seconds

#### Success Criteria
- ✅ All tests pass
- ✅ Performance targets met
- ✅ No memory leaks detected
- ✅ Error handling comprehensive

---

## Technical Architecture

### Data Flow
```
User clicks "Export PDF"
    ↓
Executive Dashboard queries materialized views
    ↓
Data passed to RMarkdown template
    ↓
pagedown::chrome_print() generates PDF
    ↓
PDF uploaded to gs://monitor-legislativo-reports
    ↓
Signed URL generated (72-hour expiration)
    ↓
Download link displayed to user
```

### Technologies
- **R Shiny**: UI framework
- **pagedown**: PDF generation
- **RMarkdown**: Report templates
- **googleCloudStorageR**: GCS integration
- **Materialized Views**: Fast data retrieval
- **Cloud Storage**: File hosting

---

## Dependencies

### R Packages (already in renv.lock)
- shiny
- bslib
- pagedown
- rmarkdown
- googleCloudStorageR
- DBI
- RPostgres

### External Services
- Google Cloud Storage (bucket already created)
- Cloud SQL PostgreSQL (materialized views ready)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| PDF generation fails | Low | Medium | Add error handling, fallback to HTML |
| Cloud Storage upload timeout | Low | Medium | Implement retry logic, progress tracking |
| Materialized views slow | Low | High | Already tested < 40ms, use REFRESH CONCURRENTLY |
| Chrome/Chromium not available | Medium | High | Use webshot2 fallback, document requirements |
| Memory usage too high | Medium | Medium | Limit concurrent exports, monitor usage |

---

## Testing Plan

### Unit Tests
- Test KPI calculation functions
- Test PDF generation with sample data
- Test HTML generation with sample data
- Test Cloud Storage upload/download
- Test signed URL generation

### Integration Tests
- End-to-end export workflow
- Multi-user concurrent exports
- Large dataset handling
- Error scenarios (network failures, missing data)

### Performance Tests
- PDF generation time with various data volumes
- Cloud Storage upload speed
- Materialized view query performance
- Memory usage during exports

---

## Success Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Export success rate | > 95% | Log exports, track failures |
| PDF generation time | < 10 seconds | Automated timing |
| User satisfaction | Positive feedback | User interviews |
| Storage usage | < 1GB/month | GCS monitoring |
| Export frequency | 10+ exports/week | Usage tracking |

---

## Rollout Plan

### Phase 1: Development (Days 1-3)
- Implement Task 2.1 (Executive UI)
- Implement Task 2.2 (PDF Export)
- Implement Task 2.3 (HTML Export)

### Phase 2: Integration (Days 4-5)
- Implement Task 2.4 (Cloud Storage)
- Implement Task 2.5 (Export Buttons)
- Connect all components

### Phase 3: Testing (Days 6-7)
- Execute Task 2.6 (Testing)
- Fix any bugs discovered
- Performance optimization

### Phase 4: Deployment
- Deploy to Cloud Run
- Monitor for issues
- Gather initial user feedback

---

## Post-Week 2 Status

Once Week 2 is complete, we will have:
- ✅ Executive dashboard with KPIs
- ✅ PDF export functionality
- ✅ HTML export functionality
- ✅ Cloud Storage integration
- ✅ Shareable report links

This sets the foundation for Week 3:
- Email delivery integration (requires Resend from Task 1.5)
- Scheduled report automation
- Report customization options

---

## Notes & Decisions

**Decision Log:**
- **2025-11-25:** Using pagedown over other PDF generators for R/Shiny compatibility
- **2025-11-25:** HTML reports will be self-contained (no external deps) for maximum portability
- **2025-11-25:** 72-hour signed URL expiration balances security and usability

**Open Questions:**
- [ ] Should we add password protection to shared reports?
- [ ] What format for report filenames? (Currently: `executive-report-YYYY-MM-DD-HHmmss.pdf`)
- [ ] Should we track report generation in database for analytics?

---

## Resources

### Documentation
- [pagedown documentation](https://pagedown.rbind.io/)
- [googleCloudStorageR guide](https://code.markedmondson.me/googleCloudStorageR/)
- [RMarkdown templates](https://rmarkdown.rstudio.com/developer_document_templates.html)

### Example Templates
- Executive report layout mockup (see PRD-BI-ENHANCEMENTS.md)
- Print CSS best practices for reports

---

**Last Updated:** 2025-11-25
**Next Review:** Start of Week 2 implementation
