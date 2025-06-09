# 🟡 HIGH-003: Missing Security Headers

## 📊 Issue Details
- **Severity**: HIGH
- **CVSS Score**: 7.1
- **Category**: Web Application Security
- **Discovery Date**: 2025-06-09
- **Status**: OPEN

## 🎯 Summary
Critical HTTP security headers are missing from web application responses, exposing the application to various client-side attacks.

## 📍 Location
**File**: `web/middleware/security_headers.py`  
**Affected**: All web application endpoints

## 🔍 Detailed Description
Analysis of HTTP responses reveals missing or improperly configured security headers that are essential for protecting against modern web attacks.

**Missing Headers:**
```http
# Currently Missing:
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

**Security Implications:**
1. **XSS Attacks**: Missing CSP allows script injection
2. **Clickjacking**: Missing X-Frame-Options enables iframe attacks
3. **MIME Sniffing**: Missing X-Content-Type-Options allows content confusion
4. **SSL Stripping**: Missing HSTS allows downgrade attacks
5. **Privacy Leaks**: Missing Referrer-Policy exposes navigation patterns

## 💥 Impact Assessment

### Security Risks:
1. **Cross-Site Scripting (XSS)**: Malicious script execution in user browsers
2. **Clickjacking**: Invisible iframe overlays tricking users into actions
3. **Content Type Confusion**: MIME sniffing leading to code execution
4. **Man-in-the-Middle**: SSL downgrade attacks on sensitive government data
5. **Information Disclosure**: Referrer leakage exposing user behavior

### Compliance Impact:
- **OWASP**: Violation of OWASP security standards
- **Government Standards**: Non-compliance with Brazilian government security guidelines
- **Audit Findings**: Security assessment failures

## 🚨 Remediation Steps

### ⚡ Immediate Actions (0-4 hours):

1. **Implement Core Security Headers**:
   ```python
   # web/middleware/security_headers.py
   from fastapi import Request, Response
   from fastapi.middleware.base import BaseHTTPMiddleware
   
   class SecurityHeadersMiddleware(BaseHTTPMiddleware):
       def __init__(self, app):
           super().__init__(app)
           self.security_headers = {
               # Prevent MIME sniffing
               "X-Content-Type-Options": "nosniff",
               
               # Prevent clickjacking
               "X-Frame-Options": "DENY",
               
               # Basic CSP (will enhance later)
               "Content-Security-Policy": "default-src 'self'",
               
               # Referrer policy
               "Referrer-Policy": "strict-origin-when-cross-origin",
               
               # Prevent XSS
               "X-XSS-Protection": "1; mode=block"
           }
       
       async def dispatch(self, request: Request, call_next):
           response = await call_next(request)
           
           # Add security headers
           for header, value in self.security_headers.items():
               response.headers[header] = value
           
           return response
   ```

2. **Configure HSTS for Production**:
   ```python
   # Add HSTS for HTTPS connections
   def add_hsts_header(request: Request, response: Response):
       if request.url.scheme == "https":
           response.headers["Strict-Transport-Security"] = (
               "max-age=31536000; includeSubDomains; preload"
           )
   ```

### 🛡️ Enhanced Security Headers (4-24 hours):

3. **Implement Comprehensive CSP**:
   ```python
   # Enhanced Content Security Policy
   CSP_POLICY = {
       "default-src": ["'self'"],
       "script-src": [
           "'self'",
           "'unsafe-inline'",  # Temporary - will remove after code cleanup
           "https://cdnjs.cloudflare.com"
       ],
       "style-src": [
           "'self'",
           "'unsafe-inline'",
           "https://fonts.googleapis.com"
       ],
       "font-src": [
           "'self'",
           "https://fonts.gstatic.com"
       ],
       "img-src": [
           "'self'",
           "data:",
           "https:"
       ],
       "connect-src": [
           "'self'",
           "https://api.gov.br",  # Government APIs
           "https://www.gov.br"
       ],
       "frame-ancestors": ["'none'"],
       "base-uri": ["'self'"],
       "form-action": ["'self'"]
   }
   
   def build_csp_header(policy: dict) -> str:
       directives = []
       for directive, sources in policy.items():
           sources_str = " ".join(sources)
           directives.append(f"{directive} {sources_str}")
       return "; ".join(directives)
   ```

4. **Add Permissions Policy**:
   ```python
   # Control browser features
   PERMISSIONS_POLICY = {
       "camera": "none",
       "microphone": "none", 
       "geolocation": "self",  # Needed for Brazilian address geocoding
       "payment": "none",
       "usb": "none",
       "autoplay": "none",
       "encrypted-media": "none"
   }
   
   def build_permissions_policy(policy: dict) -> str:
       policies = []
       for feature, allowlist in policy.items():
           if allowlist == "none":
               policies.append(f"{feature}=()")
           elif allowlist == "self":
               policies.append(f"{feature}=(self)")
           else:
               policies.append(f"{feature}=({allowlist})")
       return ", ".join(policies)
   ```

### 🔐 Advanced Security Implementation (1-7 days):

5. **Cross-Origin Policies**:
   ```python
   # Cross-Origin security
   CROSS_ORIGIN_HEADERS = {
       "Cross-Origin-Embedder-Policy": "require-corp",
       "Cross-Origin-Opener-Policy": "same-origin",
       "Cross-Origin-Resource-Policy": "same-origin"
   }
   ```

6. **Dynamic CSP with Nonces**:
   ```python
   import secrets
   from fastapi import Request
   
   def generate_csp_nonce() -> str:
       return secrets.token_urlsafe(16)
   
   def add_csp_nonce(request: Request, response: Response):
       nonce = generate_csp_nonce()
       request.state.csp_nonce = nonce
       
       csp = f"script-src 'self' 'nonce-{nonce}'; object-src 'none';"
       response.headers["Content-Security-Policy"] = csp
   ```

7. **Security Headers Testing**:
   ```python
   # Automated testing for security headers
   def test_security_headers():
       test_cases = [
           ("X-Content-Type-Options", "nosniff"),
           ("X-Frame-Options", "DENY"),
           ("Referrer-Policy", "strict-origin-when-cross-origin"),
           ("Content-Security-Policy", "default-src 'self'")
       ]
       
       for header, expected_value in test_cases:
           assert header in response.headers
           assert expected_value in response.headers[header]
   ```

## ✅ Verification Steps
- [ ] All critical security headers implemented
- [ ] HSTS configured for HTTPS connections
- [ ] Comprehensive CSP policy deployed
- [ ] Permissions Policy configured appropriately
- [ ] Cross-Origin policies implemented
- [ ] CSP nonces working for inline scripts
- [ ] Security headers testing automated

## 📋 Testing
```bash
# Test security headers with curl
curl -I https://monitor-legislativo.gov.br/

# Expected headers:
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xxx'
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Referrer-Policy: strict-origin-when-cross-origin

# Automated security testing
python -m pytest tests/security/test_security_headers.py

# Test CSP violations
python tests/security/test_csp_violations.py

# Security scanner validation
python tests/security/security_scanner.py --headers-only
```

## 🎯 Header Configuration by Environment

### Development Environment:
```python
DEV_HEADERS = {
    "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "X-Frame-Options": "SAMEORIGIN",  # Allow development tools
}
```

### Production Environment:
```python
PROD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-{nonce}'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(self)",
}
```

### API Endpoints:
```python
API_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin"
}
```

## 🛡️ Brazilian Government Compliance

### Required for Government Applications:
- **HSTS**: Mandatory for all government websites
- **CSP**: Required to prevent code injection
- **X-Frame-Options**: Prevent government site embedding
- **Referrer-Policy**: Protect user navigation privacy

### Special Considerations:
- **Government APIs**: Whitelist known government domains
- **Geographic Data**: Allow geolocation for Brazilian address services
- **Accessibility**: Ensure headers don't break screen readers
- **Mobile Support**: Headers compatible with government mobile apps

## 📞 Integration Points
- Update `web/main.py` to register middleware
- Modify `nginx/nginx.conf` for server-level headers
- Configure `kubernetes/ingress.yaml` for ingress-level headers
- Update `monitoring/grafana/` dashboards for header monitoring

## 🕐 Timeline
- **Discovery**: 2025-06-09 11:35:06
- **Core Headers**: Within 4 hours
- **Enhanced CSP**: Within 24 hours
- **Full Implementation**: Within 7 days
- **Security Audit**: 2025-06-16

---

**⚠️ Priority: HIGH - Critical for web application security before production**