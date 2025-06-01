# Network Connectivity Fix: Railway → Supabase

## 🚨 Current Issue
**Error:** `[Errno 101] Network is unreachable`
**Cause:** Supabase network restrictions blocking Railway's dynamic IPs

## ✅ Quick Fix Solutions

### Option 1: Disable Supabase Network Restrictions (Recommended)
1. Go to [Supabase Dashboard](https://supabase.com/dashboard)
2. Select your project: `monitor-legislativo-v4`
3. Navigate to **Settings** → **Database**
4. Find **Network restrictions** section
5. **Disable IP restrictions** or allow all IPs (0.0.0.0/0)
6. Save changes

### Option 2: Whitelist Railway IP Ranges
If you must keep restrictions enabled:

**US East (Railway default region):**
```
52.2.0.0/15
54.82.0.0/15
54.144.0.0/14
54.208.0.0/13
```

**US West:**
```
52.8.0.0/15
54.176.0.0/15
54.193.0.0/16
```

Add these CIDR ranges to your Supabase allowed IPs.

### Option 3: Railway Static IPs (Pro Plan - $20/month)
1. Upgrade to Railway Pro plan
2. Enable Static Outbound IPs in service settings
3. Whitelist the assigned static IP in Supabase

## 🔧 SSL Certificate Fix

The certificate error is secondary but can be fixed by copying the certificate to Railway:

```dockerfile
# Add to Railway deployment
COPY "ssl certificado.cer" /app/ssl-cert.cer
```

Update the certificate path in `supabase_config.py`:
```python
ssl_cert_path = "/app/ssl-cert.cer"
```

## 🎯 Recommended Action Plan

1. **Immediate (5 minutes):** Disable Supabase network restrictions
2. **Test:** Check if Railway can connect to database
3. **Optional:** Re-enable restrictions with Railway IP ranges
4. **Long-term:** Consider Railway Pro plan for static IPs

## 🧪 Test Commands

After making changes, test connectivity:
```bash
curl https://monitor-legislativo-v4-production.up.railway.app/api/v1/health/database
```

Expected response: Database connection successful

## 📋 Current Environment Status
- ✅ SSL configuration fixed (asyncpg compatible)
- ✅ Password encoding fixed (MonitorTransporte25%2A)
- ❌ Network connectivity blocked by Supabase firewall
- ✅ Fallback mode operational (889 CSV documents loaded)