# GitHub Personal Access Token (PAT) Setup Guide

## 1. Create a Personal Access Token on GitHub

1. **Navigate to GitHub Settings**
   - Click your profile picture → Settings
   - Scroll to "Developer settings" (bottom of left sidebar)
   - Click "Personal access tokens" → "Tokens (classic)"

2. **Generate New Token**
   - Click "Generate new token" → "Generate new token (classic)"
   - Enter a descriptive name (e.g., "CLI-Access-MacBook")
   - Set expiration (recommended: 90 days for security)

## 2. Select Required Permissions/Scopes

**For basic repository operations, select:**
- ✅ `repo` (Full control of private repositories)
  - Includes: repo:status, repo_deployment, public_repo, repo:invite

**For additional operations, consider:**
- ✅ `workflow` (Update GitHub Action workflows)
- ✅ `read:org` (Read org and team membership)
- ✅ `gist` (Create gists)

**Minimal scope for public repos only:**
- ✅ `public_repo` (Access public repositories)

## 3. Configure Git to Use the Token

### Option A: Cache credentials (Recommended)
```bash
# Configure credential helper to cache
git config --global credential.helper cache

# Set cache timeout (optional, default is 15 minutes)
git config --global credential.helper 'cache --timeout=3600'  # 1 hour

# Next git push/pull will prompt for username and password
# Username: your-github-username
# Password: your-personal-access-token
```

### Option B: Store in macOS Keychain
```bash
# For macOS users
git config --global credential.helper osxkeychain
```

### Option C: Store in Windows Credential Manager
```bash
# For Windows users
git config --global credential.helper manager
```

### Option D: Use token in remote URL (Less secure)
```bash
# Clone with token
git clone https://YOUR_TOKEN@github.com/username/repo.git

# Update existing repo
git remote set-url origin https://YOUR_TOKEN@github.com/username/repo.git
```

## 4. Security Best Practices

### DO:
- ✅ **Use minimal scopes** - Only select permissions you actually need
- ✅ **Set expiration dates** - Rotate tokens every 30-90 days
- ✅ **Use different tokens** for different machines/purposes
- ✅ **Store securely** - Use credential helpers, not plain text
- ✅ **Revoke immediately** if compromised or no longer needed

### DON'T:
- ❌ **Never commit tokens** to repositories
- ❌ **Never share tokens** with others
- ❌ **Never use tokens** in scripts without encryption
- ❌ **Never select "all scopes"** unless absolutely necessary

## Quick Test

After setup, test your configuration:
```bash
git clone https://github.com/your-username/your-private-repo.git
# Should prompt for credentials once, then cache them
```

## Troubleshooting

**Authentication failed?**
- Ensure you're using the token as the password, not your GitHub password
- Check token hasn't expired
- Verify token has correct permissions for the operation

**Token compromised?**
1. Immediately revoke on GitHub: Settings → Developer settings → Personal access tokens
2. Generate new token
3. Update all systems using the old token

## Token Rotation Reminder

Set a calendar reminder to rotate your tokens before expiration to maintain uninterrupted access.