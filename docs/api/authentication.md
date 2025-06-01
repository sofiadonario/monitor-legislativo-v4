# API Authentication

The Legislative Monitoring System uses JWT (JSON Web Tokens) for API authentication.

## Overview

- **Type**: Bearer Token (JWT)
- **Token Location**: Authorization header
- **Format**: `Authorization: Bearer <token>`
- **Expiration**: 1 hour (configurable)

## Obtaining a Token

### Login Endpoint

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password"
}
```

### Response

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Using the Token

Include the access token in the Authorization header for all authenticated requests:

```bash
curl -X GET http://localhost:5000/api/protected-endpoint \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
```

## Token Refresh

When the access token expires, use the refresh token to obtain a new one:

```http
POST /api/auth/refresh
Content-Type: application/json
Authorization: Bearer <refresh_token>
```

### Response

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600
}
```

## Protected Endpoints

The following endpoints require authentication:

- `POST /api/search` - Unified search
- `GET /api/metrics` - System metrics
- `POST /api/export` - Data export
- `PUT /api/user/profile` - Update user profile
- `DELETE /api/cache` - Clear cache

## Public Endpoints

These endpoints are accessible without authentication:

- `GET /api/health` - Health check
- `GET /api/camara/proposicoes` - Camara proposals (rate limited)
- `GET /api/senado/materias` - Senate matters (rate limited)
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration

## API Keys (Alternative)

For server-to-server communication, API keys are supported:

```bash
curl -X GET http://localhost:5000/api/protected-endpoint \
  -H "X-API-Key: your-api-key"
```

### Obtaining an API Key

API keys must be requested through the admin panel or by contacting support.

## Rate Limiting

Authentication affects rate limits:

| User Type | Requests/Hour | Requests/Minute |
|-----------|---------------|-----------------|
| Unauthenticated | 100 | 10 |
| Authenticated | 1000 | 100 |
| API Key | 5000 | 500 |

## Security Best Practices

1. **Never share tokens**: Tokens are like passwords
2. **Use HTTPS**: Always use encrypted connections
3. **Token storage**: Store tokens securely (not in localStorage for web apps)
4. **Token rotation**: Refresh tokens regularly
5. **Logout**: Invalidate tokens when logging out

## Error Responses

### 401 Unauthorized

```json
{
  "error": "unauthorized",
  "message": "Invalid or missing authentication token"
}
```

### 403 Forbidden

```json
{
  "error": "forbidden",
  "message": "You don't have permission to access this resource"
}
```

### 419 Token Expired

```json
{
  "error": "token_expired",
  "message": "The access token has expired"
}
```

## Code Examples

### Python

```python
import requests

# Login
response = requests.post('http://localhost:5000/api/auth/login', json={
    'username': 'user@example.com',
    'password': 'secure_password'
})
tokens = response.json()

# Use token
headers = {'Authorization': f"Bearer {tokens['access_token']}"}
response = requests.get('http://localhost:5000/api/protected-endpoint', headers=headers)
```

### JavaScript

```javascript
// Login
const response = await fetch('http://localhost:5000/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'user@example.com',
    password: 'secure_password'
  })
});
const tokens = await response.json();

// Use token
const data = await fetch('http://localhost:5000/api/protected-endpoint', {
  headers: {
    'Authorization': `Bearer ${tokens.access_token}`
  }
});
```

## Token Claims

JWT tokens include the following claims:

```json
{
  "sub": "user_id",
  "iat": 1706698800,
  "exp": 1706702400,
  "fresh": true,
  "type": "access",
  "roles": ["user", "admin"]
}
```

## Troubleshooting

### Token Not Working
1. Check token hasn't expired
2. Verify correct header format
3. Ensure token is complete (no truncation)

### Getting 401 Errors
1. Verify credentials are correct
2. Check if account is active
3. Ensure token is being sent correctly

### Performance Issues
1. Cache tokens appropriately
2. Don't validate on every request
3. Use connection pooling