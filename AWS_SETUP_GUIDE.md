# AWS Setup Guide - Creating IAM User for CLI Access

## ⚠️ IMPORTANT: Never Use Root Account for CLI

Your AWS root account should only be used for:
- Initial account setup
- Billing management
- Account closure
- Emergency access

## Step 1: Create IAM User via AWS Console

### 1.1 Access AWS Console
1. Go to https://aws.amazon.com/console/
2. Sign in with your **root account** (email + password)
3. Navigate to **IAM** service

### 1.2 Create New User
1. Click **"Users"** in the left sidebar
2. Click **"Add users"**
3. Enter username: `monitor-legislativo-admin`
4. Select access type: **"Programmatic access"** ✅
5. Optionally also select **"AWS Management Console access"** if you want web access

### 1.3 Set Permissions
Choose one of these options:

**Option A: Administrator Access (Easiest)**
- Click **"Attach policies directly"**
- Search for and select **"AdministratorAccess"**
- This gives full access to all AWS services

**Option B: Custom Permissions (More Secure)**
- Attach these specific policies:
  - `AmazonEC2FullAccess`
  - `AmazonS3FullAccess`
  - `AmazonRDSFullAccess`
  - `AmazonEKSClusterPolicy`
  - `AmazonEKSWorkerNodePolicy`
  - `IAMFullAccess`
  - `AmazonRoute53FullAccess`
  - `SecretsManagerReadWrite`

### 1.4 Complete User Creation
1. Review settings
2. Click **"Create user"**
3. **IMPORTANT**: Download the CSV file with credentials
4. Save the **Access Key ID** and **Secret Access Key** securely

## Step 2: Configure AWS CLI

Once you have your IAM user credentials:

```powershell
# Configure AWS CLI
aws configure

# When prompted, enter:
# AWS Access Key ID: [Your Access Key ID from CSV]
# AWS Secret Access Key: [Your Secret Access Key from CSV]
# Default region name: us-east-1
# Default output format: json
```

## Step 3: Verify Setup

```powershell
# Test AWS CLI access
aws sts get-caller-identity

# This should show your IAM user ARN, not root account
```

## Step 4: Security Best Practices

### Enable MFA (Multi-Factor Authentication)
1. In IAM Console, select your user
2. Go to **"Security credentials"** tab
3. Click **"Assign MFA device"**
4. Follow setup instructions

### Rotate Access Keys Regularly
- Create new access keys every 90 days
- Delete old keys after updating CLI configuration

## Troubleshooting

### "Access Denied" Errors
- Ensure your IAM user has the necessary permissions
- Check if policies are attached correctly

### "Invalid Credentials" Errors
- Verify Access Key ID and Secret Access Key are correct
- Ensure no extra spaces when copying credentials

### "Region Not Found" Errors
- Use valid AWS region codes (e.g., us-east-1, us-west-2)
- Check AWS documentation for available regions

## Next Steps

After AWS CLI is configured:
1. Set up S3 backend for Terraform state
2. Create DynamoDB table for state locking
3. Proceed with infrastructure provisioning

---

**Remember**: Keep your credentials secure and never commit them to version control! 