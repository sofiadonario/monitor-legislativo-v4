# Resend Email Service Setup Guide
**Monitor Legislativo v4 - Week 1 Task 1.5**

**Status:** Ready for manual signup
**Time Required:** 15 minutes
**Cost:** $0 (Free tier: 3,000 emails/month, 100 emails/day)

---

## Overview

Resend is a modern email API that will power automated legislative reports and notifications. We chose Resend over Gmail API for better deliverability, professional sending, and simpler integration.

**What we'll send:**
- Daily executive reports (PDF/HTML attachments)
- Weekly legislative summaries
- Alert notifications for urgent legislation
- Estimated volume: ~200 emails/month (well under 3,000 free tier limit)

---

## Step 1: Create Resend Account (MANUAL - YOU DO THIS)

1. **Go to:** https://resend.com/signup
2. **Sign up with:**
   - Email: Use your institutional email (e.g., sofia@mackenzie.br)
   - Password: Use a strong password (save in password manager)
3. **Verify email:** Check inbox and click verification link
4. **Complete onboarding:** Skip the tutorial if prompted

**⏱️ Time:** 3 minutes

---

## Step 2: Generate API Key (MANUAL - YOU DO THIS)

1. **Navigate to:** Dashboard → API Keys
2. **Click:** "Create API Key"
3. **Settings:**
   - Name: `monitor-legislativo-production`
   - Permission: `Sending access` (default)
   - Domain: `All domains` (we'll configure domain later)
4. **Copy the API key:** It looks like `re_123abc456def...`
   - ⚠️ **CRITICAL:** Save this immediately - you can only see it once!
   - Save in: Password manager or secure note
5. **Keep the browser tab open** until you've stored the key in GCP Secret Manager (next step)

**⏱️ Time:** 2 minutes

---

## Step 3: Store API Key in Secret Manager (RUN THESE COMMANDS)

Once you have the API key from Step 2, run these commands in your terminal:

```bash
# Set your API key as a variable (paste your actual key here)
RESEND_API_KEY="re_YOUR_ACTUAL_KEY_HERE"

# Create secret in Google Cloud Secret Manager
echo -n "$RESEND_API_KEY" | gcloud secrets create resend-api-key \
  --data-file=- \
  --replication-policy="automatic" \
  --project=mackmonitor

# Verify secret was created
gcloud secrets describe resend-api-key --project=mackmonitor

# Grant Cloud Run access to the secret
gcloud secrets add-iam-policy-binding resend-api-key \
  --member="serviceAccount:667999538255-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor" \
  --project=mackmonitor

# Verify permissions
gcloud secrets get-iam-policy resend-api-key --project=mackmonitor
```

**Expected output:**
```
Created secret [resend-api-key].
✅ Secret stored successfully
✅ Cloud Run service account has access
```

**⏱️ Time:** 2 minutes

---

## Step 4: Test Email Sending (RUN THIS TEST)

Create a test script to verify email delivery:

```bash
# Create test email script
cat > /tmp/test-resend.sh <<'EOF'
#!/bin/bash

# Get API key from Secret Manager
RESEND_API_KEY=$(gcloud secrets versions access latest --secret=resend-api-key --project=mackmonitor)

# Send test email
curl -X POST https://api.resend.com/emails \
  -H "Authorization: Bearer $RESEND_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "Monitor Legislativo <noreply@resend.dev>",
    "to": ["YOUR_EMAIL@example.com"],
    "subject": "Test: Monitor Legislativo Email Setup",
    "html": "<h1>✅ Email Setup Successful!</h1><p>This is a test email from Monitor Legislativo v4.</p><p>If you received this, the Resend integration is working correctly.</p>"
  }' | jq '.'

echo ""
echo "✅ If you see an 'id' in the response above, the email was sent successfully!"
echo "📧 Check your inbox (and spam folder) for the test email."
EOF

chmod +x /tmp/test-resend.sh

# Run the test (replace YOUR_EMAIL@example.com with your actual email)
sed -i '' 's/YOUR_EMAIL@example.com/sofia.donario@example.com/g' /tmp/test-resend.sh
/tmp/test-resend.sh
```

**Expected response:**
```json
{
  "id": "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794",
  "from": "Monitor Legislativo <noreply@resend.dev>",
  "to": ["sofia.donario@example.com"],
  "created_at": "2025-11-27T14:15:00.000Z"
}
```

**⏱️ Time:** 3 minutes

---

## Step 5: Configure Email Templates (OPTIONAL BUT RECOMMENDED)

### Brazilian Portuguese Email Template

Create a professional template for legislative reports:

```html
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Monitor Legislativo - Relatório</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 8px 8px 0 0;
      text-align: center;
    }
    .content {
      background: white;
      padding: 30px;
      border-radius: 0 0 8px 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .button {
      display: inline-block;
      padding: 12px 24px;
      background: #667eea;
      color: white;
      text-decoration: none;
      border-radius: 4px;
      margin: 20px 0;
    }
    .footer {
      text-align: center;
      margin-top: 20px;
      font-size: 12px;
      color: #666;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>📊 Monitor Legislativo</h1>
    <p>Relatório Executivo</p>
  </div>

  <div class="content">
    <h2>Olá!</h2>

    <p>Seu relatório executivo está disponível para download.</p>

    <p><strong>Período:</strong> {{period}}</p>
    <p><strong>Documentos analisados:</strong> {{document_count}}</p>
    <p><strong>Estados cobertos:</strong> {{states_count}}</p>

    <a href="{{download_url}}" class="button">📥 Baixar Relatório</a>

    <p><small>O link expira em 72 horas.</small></p>

    <hr>

    <p><strong>Destaques do período:</strong></p>
    <ul>
      {{highlights}}
    </ul>
  </div>

  <div class="footer">
    <p>Monitor Legislativo v4 - Monitoramento de Legislação Brasileira</p>
    <p>Universidade Presbiteriana Mackenzie</p>
  </div>
</body>
</html>
```

**Save this as:** `R/templates/email_report_template.html`

**⏱️ Time:** 5 minutes (optional)

---

## Step 6: Domain Verification (OPTIONAL - For Production)

To send emails from your own domain (e.g., `reports@monitor-legislativo.com.br`) instead of `noreply@resend.dev`:

### 6.1 Add Domain in Resend Dashboard

1. Go to: Dashboard → Domains
2. Click: "Add Domain"
3. Enter: `monitor-legislativo.com.br` (or your preferred domain)
4. Resend will provide DNS records to add

### 6.2 Add DNS Records

You'll need to add these records to your domain's DNS:

```
Type: TXT
Name: resend._domainkey.monitor-legislativo.com.br
Value: [provided by Resend]

Type: MX
Name: monitor-legislativo.com.br
Value: [provided by Resend]
Priority: 10
```

### 6.3 Verify Domain

- Wait 5-10 minutes for DNS propagation
- Click "Verify" in Resend dashboard
- Once verified, you can send from `@monitor-legislativo.com.br`

**⏱️ Time:** 15 minutes (optional, can do later)

---

## Step 7: Integration Checklist

Once API key is stored in Secret Manager, verify:

- [ ] Secret `resend-api-key` exists in Secret Manager
- [ ] Cloud Run service account has `secretAccessor` role
- [ ] Test email sent successfully (check inbox)
- [ ] Test email not in spam folder
- [ ] Response includes valid `id` field

**Ready for Week 3!** ✅

---

## Configuration Summary

**What's configured:**
- ✅ Resend account created
- ✅ API key generated and stored securely
- ✅ Email sending tested and working
- ✅ Cloud Run has access to API key

**What's next (Week 3):**
- Create email delivery module in R
- Integrate with report generation
- Set up scheduled email jobs
- Add recipient management UI

---

## Troubleshooting

### Issue: API key not working

**Check:**
```bash
# Verify secret exists
gcloud secrets versions access latest --secret=resend-api-key --project=mackmonitor

# Test manually
curl -X POST https://api.resend.com/emails \
  -H "Authorization: Bearer $(gcloud secrets versions access latest --secret=resend-api-key --project=mackmonitor)" \
  -H "Content-Type: application/json" \
  -d '{"from":"onboarding@resend.dev","to":["test@example.com"],"subject":"Test","html":"<p>Test</p>"}'
```

### Issue: Emails going to spam

**Solutions:**
1. Verify domain (see Step 6)
2. Add SPF and DKIM records
3. Use professional "from" address
4. Include unsubscribe link in templates
5. Warm up sending (start with low volume)

### Issue: Rate limit exceeded

**Free tier limits:**
- 3,000 emails/month
- 100 emails/day

**Solutions:**
1. Monitor usage: Dashboard → Usage
2. Upgrade plan if needed ($20/month = 50,000 emails)
3. Implement email batching for large recipient lists

---

## Cost Analysis

**Free Tier (Current):**
- 3,000 emails/month
- 100 emails/day
- Enough for: 200 reports/month

**Projected Usage:**
- Daily reports: 30/month
- Weekly summaries: 4/month
- Urgent alerts: ~20/month
- Testing: ~10/month
- **Total: ~64 emails/month**

**Conclusion:** Free tier is more than sufficient! 💰

---

## Next Steps

After completing this setup:

1. **Update projectplan.md:**
   - Mark Task 1.5 as complete ✅
   - Update Week 1 status to 100%

2. **Ready for Week 3:**
   - Task 3.1: ✅ Complete (Resend ready)
   - Task 3.2: Email delivery module (next)
   - Task 3.3: Scheduled automation
   - Task 3.4: Recipient management

3. **Test once deployed:**
   - Generate test report
   - Send via Resend
   - Verify delivery
   - Check formatting

---

## Quick Reference

**Resend Dashboard:** https://resend.com/dashboard
**API Documentation:** https://resend.com/docs
**Status Page:** https://status.resend.com

**Key commands:**
```bash
# Get API key
gcloud secrets versions access latest --secret=resend-api-key --project=mackmonitor

# Send test email
curl -X POST https://api.resend.com/emails \
  -H "Authorization: Bearer $(gcloud secrets versions access latest --secret=resend-api-key --project=mackmonitor)" \
  -H "Content-Type: application/json" \
  -d '{"from":"Monitor Legislativo <noreply@resend.dev>","to":["your@email.com"],"subject":"Test","html":"<p>Test</p>"}'

# Check recent emails
# (Visit dashboard - no CLI for this)
```

---

**Last Updated:** 2025-11-27
**Status:** Ready for user signup and API key generation
