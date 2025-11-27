# Week 3 Testing & Validation Guide
**Monitor Legislativo v4 - Email Delivery & Automation**

**Date:** 2025-11-27
**Version:** 1.0
**Status:** Ready for execution once deployed

---

## Overview

This guide provides comprehensive testing procedures for all Week 3 features:
- Email delivery via Resend
- Automated report scheduling
- Recipient management
- End-to-end report workflows

**Prerequisites:**
- ✅ Deployment successful (build 640c41cb or later)
- ✅ Resend API key configured
- ✅ Database migrations applied
- ✅ Cloud Scheduler jobs created

---

## Test Suite 1: Email Delivery (Core Functionality)

### Test 1.1: API Key Retrieval
**Objective:** Verify Resend API key can be retrieved from Secret Manager

**Steps:**
```r
# In R console or RStudio
source("R/utils/email_sender.R")
api_key <- get_resend_api_key()
print(api_key)
```

**Expected Result:**
- API key retrieved successfully
- Starts with `re_`
- No errors or warnings

**Pass Criteria:** ✅ API key retrieved and valid

---

### Test 1.2: Simple Test Email
**Objective:** Send basic test email to verify Resend integration

**Steps:**
```r
source("R/utils/email_sender.R")
result <- test_email_sending(to = "sofiadonario@hotmail.com")
print(result)
```

**Expected Result:**
```r
$status
[1] "success"

$email_id
[1] "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

$timestamp
[1] "2025-11-27 14:30:00 -03"
```

**Verification:**
- ✅ Status is "success"
- ✅ Email ID returned
- ✅ Email received in inbox (check sofiadonario@hotmail.com)
- ✅ Email not in spam folder
- ✅ Formatting looks correct

**Pass Criteria:** ✅ Email received within 1 minute

---

### Test 1.3: HTML Email with Template
**Objective:** Test template-based email generation

**Steps:**
```r
source("R/utils/email_sender.R")

# Sample report data
report_data <- list(
  period = "26/11/2025 a 27/11/2025",
  document_count = "132,685",
  states_count = "28",
  new_documents = "156",
  highlights = "<li>156 novos documentos nos últimos 7 dias</li><li>28 estados monitorados</li>",
  document_types = "Leis, Decretos, Portarias"
)

result <- send_report_email(
  to = "sofiadonario@hotmail.com",
  report_data = report_data,
  report_url = "https://example.com/report.pdf"
)

print(result)
```

**Expected Result:**
- Email sent successfully
- Template variables replaced correctly
- Download link works
- Formatting is professional

**Pass Criteria:** ✅ Templated email received with correct data

---

### Test 1.4: Email with PDF Attachment
**Objective:** Verify email can send PDF attachments

**Steps:**
```r
source("R/utils/kpi_calculations.R")
source("R/utils/pdf_generator.R")
source("R/utils/email_sender.R")

# Generate test PDF
kpis <- get_executive_kpis(pool)
state_summary <- get_state_summary(pool, top_n = 10)
monthly_trends <- get_monthly_trends(pool, months = 12)

pdf_path <- generate_executive_pdf(kpis, state_summary, monthly_trends)

# Send with attachment
report_data <- list(
  period = format(Sys.Date(), "%d/%m/%Y"),
  document_count = format(kpis$total_documents, big.mark = "."),
  states_count = kpis$states_covered,
  new_documents = format(kpis$docs_last_7_days, big.mark = ".")
)

result <- send_report_email(
  to = "sofiadonario@hotmail.com",
  report_data = report_data,
  report_url = "https://example.com/report.pdf",
  attachment_path = pdf_path
)
```

**Expected Result:**
- Email sent with PDF attached
- Attachment opens correctly
- File size reasonable (< 5MB)

**Pass Criteria:** ✅ Email with valid PDF attachment received

---

## Test Suite 2: Database & Recipients

### Test 2.1: Database Migration
**Objective:** Verify report_recipients table created correctly

**Steps:**
```bash
# Run migration
PGPASSWORD="Sdonario1" psql \
  -h 34.39.228.246 \
  -U postgres \
  -d monitor_legislativo \
  -f database/migrations/004_create_report_recipients.sql
```

**Verification Queries:**
```sql
-- Check table exists
SELECT COUNT(*) FROM report_recipients;

-- Check default recipient
SELECT * FROM report_recipients WHERE email = 'sofiadonario@hotmail.com';

-- Check views
SELECT COUNT(*) FROM v_daily_recipients;
SELECT COUNT(*) FROM v_weekly_recipients;
SELECT COUNT(*) FROM v_monthly_recipients;
```

**Expected Result:**
- Table created with all columns
- Default recipient exists
- Views return data
- Triggers and indexes created

**Pass Criteria:** ✅ All queries execute without errors

---

### Test 2.2: Add New Recipient (Manual SQL)
**Objective:** Test recipient insertion via SQL

**Steps:**
```sql
INSERT INTO report_recipients (
  email, name, role, organization,
  daily_reports, weekly_reports, monthly_reports
) VALUES (
  'test@example.com',
  'Test User',
  'Tester',
  'Test Organization',
  TRUE, FALSE, FALSE
);

SELECT * FROM report_recipients WHERE email = 'test@example.com';
```

**Expected Result:**
- Recipient inserted successfully
- Auto-generated ID assigned
- Timestamps set automatically
- Default values applied

**Pass Criteria:** ✅ Recipient created with correct values

---

### Test 2.3: Recipient Management UI
**Objective:** Test UI for managing recipients

**Steps:**
1. Navigate to Recipient Management tab in app
2. Click "Adicionar Destinatário"
3. Fill in form:
   - Email: test2@example.com
   - Name: Test User 2
   - Check "Relatórios Semanais"
   - Uncheck "Relatórios Diários"
4. Click "Salvar"
5. Verify recipient appears in table
6. Click on recipient to edit
7. Change preferences
8. Save and verify changes

**Expected Result:**
- Form validation works (invalid emails rejected)
- Recipients save to database
- Table updates immediately
- Edit functionality works
- Portuguese labels correct

**Pass Criteria:** ✅ All CRUD operations work correctly

---

## Test Suite 3: Cloud Scheduler & Automation

### Test 3.1: Create Scheduler Jobs
**Objective:** Set up automated report jobs

**Steps:**
```bash
cd /path/to/project
./scripts/setup-cloud-scheduler.sh
```

**Expected Result:**
```
✅ Daily executive report job created
✅ Weekly summary report job created
✅ Monthly comprehensive report job created
```

**Verification:**
```bash
gcloud scheduler jobs list --location=southamerica-east1 --project=mackmonitor
```

**Expected Output:**
```
NAME                           SCHEDULE        STATE    TARGET
daily-executive-report         0 11 * * *      ENABLED  /api/reports/daily-executive
weekly-summary-report          0 12 * * MON    ENABLED  /api/reports/weekly-summary
monthly-comprehensive-report   0 13 1 * *      ENABLED  /api/reports/monthly-comprehensive
```

**Pass Criteria:** ✅ All 3 jobs created and enabled

---

### Test 3.2: Manual Job Trigger (Daily Report)
**Objective:** Test scheduler job execution manually

**Steps:**
```bash
gcloud scheduler jobs run daily-executive-report \
  --location=southamerica-east1 \
  --project=mackmonitor
```

**Monitor logs:**
```bash
# Watch Cloud Run logs
gcloud logging read \
  'resource.type="cloud_run_revision" AND textPayload:"Daily Executive Report"' \
  --limit=50 \
  --project=mackmonitor \
  --format="table(timestamp,textPayload)"
```

**Expected Result:**
- Job triggers successfully
- API endpoint receives request
- Report generated
- PDF uploaded to Cloud Storage
- Email sent to recipients
- Logs show complete workflow

**Verification Checklist:**
- ✅ Scheduler job executes
- ✅ Cloud Run receives request
- ✅ KPIs fetched from database
- ✅ PDF generated successfully
- ✅ File uploaded to GCS
- ✅ Signed URL created
- ✅ Email sent to all daily recipients
- ✅ Email received in inbox

**Pass Criteria:** ✅ Email received within 5 minutes of trigger

---

### Test 3.3: Weekly Report Trigger
**Objective:** Test weekly report generation

**Steps:**
```bash
gcloud scheduler jobs run weekly-summary-report \
  --location=southamerica-east1 \
  --project=mackmonitor
```

**Expected Result:**
- Weekly report generated with 7-day data
- Email subject indicates "weekly"
- Report covers last 7 days
- Email sent to weekly recipients only

**Pass Criteria:** ✅ Weekly report received with correct date range

---

## Test Suite 4: End-to-End Workflows

### Test 4.1: Complete Daily Report Workflow
**Objective:** Test entire automated daily report process

**Workflow:**
```
1. Add test recipient →
2. Trigger scheduler →
3. Generate report →
4. Upload to GCS →
5. Send email →
6. Verify receipt
```

**Steps:**
1. Add recipient via UI (enable daily reports)
2. Trigger job: `gcloud scheduler jobs run daily-executive-report`
3. Wait 5 minutes
4. Check recipient inbox
5. Open email and verify:
   - Subject correct
   - Content populated
   - Download link works
   - PDF opens and looks good
6. Check GCS bucket:
   ```bash
   gsutil ls gs://monitor-legislativo-reports/
   ```

**Pass Criteria:**
- ✅ Recipient receives email
- ✅ Download link works
- ✅ PDF is valid and complete
- ✅ File in GCS bucket
- ✅ Signed URL expires after 72 hours

---

### Test 4.2: Multi-Recipient Test
**Objective:** Verify emails sent to multiple recipients

**Steps:**
1. Add 3 test recipients (use alias emails if available)
2. Trigger daily report
3. Verify all 3 receive email
4. Check each has correct preferences applied

**Pass Criteria:** ✅ All active recipients receive emails

---

### Test 4.3: Preference Respect Test
**Objective:** Verify recipient preferences are honored

**Setup:**
- Recipient A: Daily=YES, Weekly=NO
- Recipient B: Daily=NO, Weekly=YES
- Recipient C: Daily=YES, Weekly=YES

**Tests:**
1. Trigger daily report → Only A and C receive
2. Trigger weekly report → Only B and C receive

**Pass Criteria:** ✅ Emails sent only to opted-in recipients

---

## Test Suite 5: Error Handling & Edge Cases

### Test 5.1: Invalid Email Handling
**Objective:** Verify system handles invalid emails gracefully

**Steps:**
1. Try adding recipient with invalid email: "notanemail"
2. Try adding duplicate email
3. Try sending to non-existent email

**Expected Result:**
- Validation rejects invalid format
- Duplicate email rejected
- Send fails gracefully with error message
- No crashes or exceptions

**Pass Criteria:** ✅ All errors handled gracefully

---

### Test 5.2: API Key Missing
**Objective:** Test behavior when API key unavailable

**Steps:**
1. Temporarily remove API key secret
2. Try sending email
3. Restore API key

**Expected Result:**
- Clear error message
- App continues running
- Other features unaffected

**Pass Criteria:** ✅ Graceful degradation works

---

### Test 5.3: Database Connection Loss
**Objective:** Test resilience to database issues

**Steps:**
1. Simulate database unavailable
2. Try accessing recipient management
3. Try triggering scheduled report

**Expected Result:**
- User-friendly error messages
- No crashes
- Automatic retry on reconnect

**Pass Criteria:** ✅ App handles database errors gracefully

---

### Test 5.4: Large Attachment Handling
**Objective:** Verify system handles large PDF files

**Steps:**
1. Generate report with 12 months of data
2. Check file size
3. Send via email

**Expected Result:**
- PDF < 10MB (Resend limit: 40MB)
- Email sends successfully
- Download completes quickly

**Pass Criteria:** ✅ Large attachments handled correctly

---

## Test Suite 6: Performance & Scalability

### Test 6.1: Report Generation Speed
**Objective:** Measure report generation performance

**Metrics to collect:**
- KPI query time: < 50ms
- PDF generation: < 10 seconds
- GCS upload: < 3 seconds
- Email send: < 2 seconds
- Total workflow: < 20 seconds

**Test:**
```r
start_time <- Sys.time()
# Run complete workflow
end_time <- Sys.time()
duration <- difftime(end_time, start_time, units = "secs")
cat("Total time:", duration, "seconds\n")
```

**Pass Criteria:** ✅ Complete workflow < 30 seconds

---

### Test 6.2: Concurrent Report Generation
**Objective:** Test multiple simultaneous report requests

**Steps:**
1. Trigger daily report
2. Immediately trigger weekly report
3. Check both complete successfully

**Pass Criteria:** ✅ Both reports generated without conflicts

---

### Test 6.3: Bulk Recipients (10+ users)
**Objective:** Test email sending to many recipients

**Steps:**
1. Add 10 test recipients
2. Trigger report
3. Verify all receive emails

**Pass Criteria:** ✅ All 10 recipients receive email within 5 minutes

---

## Test Suite 7: Security & Compliance

### Test 7.1: Secret Manager Security
**Objective:** Verify API key stored securely

**Checks:**
- ✅ API key not in source code
- ✅ API key not in logs
- ✅ API key in Secret Manager only
- ✅ Proper IAM permissions

**Verification:**
```bash
# Check IAM policy
gcloud secrets get-iam-policy resend-api-key --project=mackmonitor
```

**Pass Criteria:** ✅ Only authorized service accounts have access

---

### Test 7.2: Email Content Security
**Objective:** Verify no sensitive data in emails

**Checks:**
- ✅ No database credentials
- ✅ No API keys
- ✅ No internal URLs
- ✅ No PII (except aggregated counts)

**Pass Criteria:** ✅ Emails contain only public-safe data

---

### Test 7.3: Unsubscribe Mechanism
**Objective:** Verify recipients can opt out

**Steps:**
1. Set recipient to inactive in UI
2. Trigger report
3. Verify recipient doesn't receive email

**Pass Criteria:** ✅ Inactive recipients don't receive emails

---

## Regression Testing Checklist

After deploying Week 3 features, verify Week 1 & 2 still work:

### Week 1 Features:
- ✅ Cloud Storage bucket accessible
- ✅ Materialized views still fast (< 50ms)
- ✅ SSL connections working
- ✅ Read-only user can connect

### Week 2 Features:
- ✅ Executive Summary tab loads
- ✅ KPI calculations correct
- ✅ Export buttons visible (even if disabled)
- ✅ App doesn't crash on startup

---

## Post-Deployment Validation

Once deployment succeeds, run this quick checklist:

1. **App Loads:** ✅ Visit app URL, no errors
2. **Executive Tab:** ✅ Navigate to Executive Summary
3. **Email Module:** ✅ Source email_sender.R, no errors
4. **Test Email:** ✅ Send test email, receive it
5. **Database:** ✅ Query report_recipients table
6. **Scheduler:** ✅ List scheduler jobs
7. **Manual Trigger:** ✅ Run one job, receive email

**Time estimate:** 15 minutes

---

## Troubleshooting Guide

### Issue: Email not received
**Solutions:**
1. Check spam folder
2. Verify Resend API key valid
3. Check recipient email is verified in Resend
4. Check Cloud Run logs for errors
5. Verify recipient is active in database

### Issue: PDF generation fails
**Solutions:**
1. Check pagedown package installed
2. Verify Chrome/Chromium available
3. Check sufficient memory
4. Try generating locally first

### Issue: Scheduler job fails
**Solutions:**
1. Check service account permissions
2. Verify Cloud Run URL correct
3. Check API endpoint exists
4. Review Cloud Run logs

### Issue: Database connection fails
**Solutions:**
1. Verify database accessible
2. Check SSL certificates valid
3. Test connection with psql
4. Review connection pool settings

---

## Success Criteria Summary

**Week 3 is considered COMPLETE when:**

✅ **Email Delivery (4/4)**
- API key retrieval works
- Test email sends and arrives
- Template emails render correctly
- Attachments work

✅ **Recipients (3/3)**
- Database table created
- UI CRUD operations work
- Preferences respected

✅ **Automation (3/3)**
- Scheduler jobs created
- Manual triggers work
- Automated sends work

✅ **Performance (3/3)**
- Reports generate < 30 seconds
- Emails arrive < 5 minutes
- No memory leaks

✅ **Regression (2/2)**
- Week 1 features work
- Week 2 features work

**Total: 15/15 tests passing = ✅ COMPLETE**

---

## Next Steps After Testing

1. **Monitor First 24 Hours:**
   - Watch scheduler executions
   - Check error rates
   - Monitor email deliverability

2. **Gather Feedback:**
   - Ask recipients about email quality
   - Check report accuracy
   - Note any issues

3. **Optimize:**
   - Tune report generation speed
   - Improve email templates
   - Adjust schedules if needed

4. **Document:**
   - Update user guide
   - Create admin handbook
   - Document common issues

---

**Testing Guide Version:** 1.0
**Last Updated:** 2025-11-27
**Next Review:** After first production deployment
