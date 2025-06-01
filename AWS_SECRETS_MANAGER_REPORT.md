# AWS Secrets Manager Configuration Report

## Executive Summary

This report details all sensitive information that must be stored in AWS Secrets Manager for the Monitor Legislativo v4 application. The secrets are organized by category, with rotation policies, access patterns, and security recommendations.

## Secret Categories and Details

### 1. Database Credentials

#### PostgreSQL Primary Database
- **Secret Name**: `monitor-legislativo/production/database/primary`
- **Contents**:
  ```json
  {
    "host": "monitor-legislativo-db.cluster-xxxxx.us-east-1.rds.amazonaws.com",
    "port": 5432,
    "database": "monitor_legislativo",
    "username": "ml_app_user",
    "password": "auto-generated-strong-password",
    "ssl_mode": "require",
    "connection_string": "postgresql://username:password@host:port/database?sslmode=require"
  }
  ```
- **Rotation**: Every 90 days
- **Access**: API pods, Worker pods, Migration jobs

#### PostgreSQL Read Replicas
- **Secret Name**: `monitor-legislativo/production/database/read-replica`
- **Contents**:
  ```json
  {
    "hosts": [
      "monitor-legislativo-db-ro-1.cluster-xxxxx.us-east-1.rds.amazonaws.com",
      "monitor-legislativo-db-ro-2.cluster-xxxxx.us-east-1.rds.amazonaws.com"
    ],
    "port": 5432,
    "database": "monitor_legislativo",
    "username": "ml_readonly_user",
    "password": "auto-generated-strong-password",
    "ssl_mode": "require"
  }
  ```
- **Rotation**: Every 90 days
- **Access**: API pods (read operations), Analytics jobs

#### Database Admin Credentials
- **Secret Name**: `monitor-legislativo/production/database/admin`
- **Contents**:
  ```json
  {
    "host": "monitor-legislativo-db.cluster-xxxxx.us-east-1.rds.amazonaws.com",
    "port": 5432,
    "database": "postgres",
    "username": "ml_admin",
    "password": "auto-generated-strong-password",
    "ssl_mode": "require"
  }
  ```
- **Rotation**: Every 30 days
- **Access**: DBA team only, Migration pipelines

### 2. Cache Credentials

#### Redis Primary
- **Secret Name**: `monitor-legislativo/production/redis/primary`
- **Contents**:
  ```json
  {
    "host": "monitor-legislativo-redis.xxxxx.cache.amazonaws.com",
    "port": 6379,
    "auth_token": "auto-generated-auth-token",
    "ssl": true,
    "connection_string": "rediss://:auth_token@host:port/0"
  }
  ```
- **Rotation**: Every 180 days
- **Access**: API pods, Worker pods

#### Redis Queue
- **Secret Name**: `monitor-legislativo/production/redis/queue`
- **Contents**:
  ```json
  {
    "host": "monitor-legislativo-queue.xxxxx.cache.amazonaws.com",
    "port": 6379,
    "auth_token": "auto-generated-auth-token",
    "ssl": true,
    "database": 1
  }
  ```
- **Rotation**: Every 180 days
- **Access**: Worker pods, Scheduler pods

### 3. Search Engine Credentials

#### OpenSearch/Elasticsearch
- **Secret Name**: `monitor-legislativo/production/opensearch/main`
- **Contents**:
  ```json
  {
    "endpoint": "https://monitor-legislativo-search.us-east-1.es.amazonaws.com",
    "username": "ml_search_user",
    "password": "auto-generated-strong-password",
    "api_key": "base64-encoded-api-key",
    "indices": {
      "documents": "ml_documents",
      "alerts": "ml_alerts",
      "logs": "ml_logs"
    }
  }
  ```
- **Rotation**: Every 90 days
- **Access**: API pods, Worker pods, Log aggregators

### 4. Authentication & Security

#### JWT Secrets
- **Secret Name**: `monitor-legislativo/production/auth/jwt`
- **Contents**:
  ```json
  {
    "access_token_secret": "256-bit-random-secret",
    "refresh_token_secret": "256-bit-random-secret",
    "algorithm": "HS256",
    "access_token_expiry_minutes": 15,
    "refresh_token_expiry_days": 30,
    "issuer": "monitor-legislativo-api"
  }
  ```
- **Rotation**: Every 180 days (with grace period)
- **Access**: API pods only

#### OAuth2 Providers
- **Secret Name**: `monitor-legislativo/production/auth/oauth`
- **Contents**:
  ```json
  {
    "google": {
      "client_id": "xxxxx.apps.googleusercontent.com",
      "client_secret": "google-oauth-secret",
      "redirect_uri": "https://api.monitorlegislativo.com/auth/google/callback"
    },
    "microsoft": {
      "client_id": "azure-ad-client-id",
      "client_secret": "azure-ad-secret",
      "tenant_id": "azure-tenant-id",
      "redirect_uri": "https://api.monitorlegislativo.com/auth/microsoft/callback"
    }
  }
  ```
- **Rotation**: Manual (coordinate with providers)
- **Access**: API pods only

#### API Keys for Internal Services
- **Secret Name**: `monitor-legislativo/production/auth/api-keys`
- **Contents**:
  ```json
  {
    "monitoring_api_key": "monitoring-service-api-key",
    "admin_api_key": "admin-dashboard-api-key",
    "mobile_api_key": "mobile-app-api-key",
    "webhook_signing_secret": "webhook-hmac-secret"
  }
  ```
- **Rotation**: Every 90 days
- **Access**: Specific service accounts

### 5. External API Credentials

#### Government APIs
- **Secret Name**: `monitor-legislativo/production/external-apis/government`
- **Contents**:
  ```json
  {
    "camara": {
      "api_key": "camara-api-key-if-required",
      "rate_limit_override": "special-agreement-token"
    },
    "senado": {
      "api_key": "senado-api-key-if-required",
      "oauth_token": "senado-oauth-token"
    },
    "planalto": {
      "access_token": "planalto-access-token"
    },
    "tse": {
      "username": "tse-api-user",
      "password": "tse-api-password"
    }
  }
  ```
- **Rotation**: Varies by provider
- **Access**: Worker pods, API pods (specific endpoints)

#### Third-Party Services
- **Secret Name**: `monitor-legislativo/production/external-apis/third-party`
- **Contents**:
  ```json
  {
    "sendgrid": {
      "api_key": "SG.xxxxxxxxxxxx",
      "from_email": "noreply@monitorlegislativo.com",
      "templates": {
        "alert": "d-template-id-1",
        "welcome": "d-template-id-2"
      }
    },
    "twilio": {
      "account_sid": "ACxxxxxxxxxxxxxxxx",
      "auth_token": "twilio-auth-token",
      "from_number": "+1234567890"
    },
    "aws_ses": {
      "smtp_username": "ses-smtp-username",
      "smtp_password": "ses-smtp-password",
      "from_email": "alerts@monitorlegislativo.com"
    }
  }
  ```
- **Rotation**: Every 180 days
- **Access**: Notification service pods

### 6. Monitoring & Observability

#### Monitoring Services
- **Secret Name**: `monitor-legislativo/production/monitoring/services`
- **Contents**:
  ```json
  {
    "datadog": {
      "api_key": "datadog-api-key",
      "app_key": "datadog-app-key",
      "site": "datadoghq.com"
    },
    "new_relic": {
      "license_key": "new-relic-license-key",
      "api_key": "new-relic-api-key"
    },
    "sentry": {
      "dsn": "https://public@sentry.io/project-id",
      "auth_token": "sentry-auth-token"
    },
    "pagerduty": {
      "integration_key": "pagerduty-integration-key"
    }
  }
  ```
- **Rotation**: Every 365 days
- **Access**: All pods (read), Admin pods (write)

#### Log Aggregation
- **Secret Name**: `monitor-legislativo/production/monitoring/logs`
- **Contents**:
  ```json
  {
    "cloudwatch": {
      "log_group": "/aws/containerinsights/monitor-legislativo/application",
      "log_stream_prefix": "ml-"
    },
    "elasticsearch_logs": {
      "endpoint": "https://logs-cluster.us-east-1.es.amazonaws.com",
      "username": "ml_logs_writer",
      "password": "logs-password",
      "index_pattern": "ml-logs-*"
    }
  }
  ```
- **Rotation**: Every 180 days
- **Access**: All pods

### 7. Encryption Keys

#### Data Encryption
- **Secret Name**: `monitor-legislativo/production/encryption/data`
- **Contents**:
  ```json
  {
    "master_key": "base64-encoded-256-bit-key",
    "pii_encryption_key": "base64-encoded-256-bit-key",
    "file_encryption_key": "base64-encoded-256-bit-key",
    "key_derivation_salt": "random-salt-value"
  }
  ```
- **Rotation**: Every 365 days (with key versioning)
- **Access**: API pods, Worker pods

#### Backup Encryption
- **Secret Name**: `monitor-legislativo/production/encryption/backup`
- **Contents**:
  ```json
  {
    "backup_encryption_key": "base64-encoded-256-bit-key",
    "backup_hmac_key": "base64-encoded-256-bit-key",
    "s3_sse_customer_key": "base64-encoded-256-bit-key"
  }
  ```
- **Rotation**: Every 365 days
- **Access**: Backup jobs only

### 8. Infrastructure Secrets

#### Container Registry
- **Secret Name**: `monitor-legislativo/production/infrastructure/registry`
- **Contents**:
  ```json
  {
    "ecr_registry": "123456789012.dkr.ecr.us-east-1.amazonaws.com",
    "dockerhub": {
      "username": "monitorlegislativo",
      "password": "dockerhub-access-token"
    }
  }
  ```
- **Rotation**: Every 180 days
- **Access**: CI/CD pipelines, K8s nodes

#### CI/CD Secrets
- **Secret Name**: `monitor-legislativo/production/infrastructure/cicd`
- **Contents**:
  ```json
  {
    "github": {
      "app_id": "github-app-id",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
      "webhook_secret": "github-webhook-secret"
    },
    "sonarqube": {
      "token": "sonarqube-project-token",
      "url": "https://sonarqube.internal.com"
    },
    "artifactory": {
      "username": "ci-user",
      "api_key": "artifactory-api-key"
    }
  }
  ```
- **Rotation**: Every 90 days
- **Access**: CI/CD service accounts

## Security Best Practices

### 1. Access Control
- Use IAM roles for service accounts (IRSA) in EKS
- Implement least privilege access
- Use separate secrets for different environments
- Enable AWS Secrets Manager access logging

### 2. Rotation Policies
- Implement automatic rotation for all database passwords
- Use dual secrets during rotation grace period
- Test rotation procedures in staging environment
- Monitor rotation failures

### 3. Encryption
- Enable encryption at rest for all secrets
- Use customer-managed KMS keys
- Implement envelope encryption for sensitive data
- Rotate encryption keys annually

### 4. Auditing
- Enable CloudTrail logging for all secret access
- Set up alerts for unauthorized access attempts
- Review access logs monthly
- Implement anomaly detection

### 5. Backup and Recovery
- Backup secrets to a separate AWS account
- Test recovery procedures quarterly
- Document secret recovery process
- Maintain offline backups for critical secrets

## Implementation Checklist

- [ ] Create all secrets in AWS Secrets Manager
- [ ] Configure automatic rotation for applicable secrets
- [ ] Set up IAM roles and policies
- [ ] Configure IRSA for EKS service accounts
- [ ] Implement secret versioning
- [ ] Set up monitoring and alerting
- [ ] Document emergency access procedures
- [ ] Create runbooks for rotation failures
- [ ] Implement secret scanning in CI/CD
- [ ] Train team on secret management

## Emergency Procedures

### Secret Compromise
1. Immediately rotate the compromised secret
2. Update all services using the secret
3. Review access logs for unauthorized usage
4. Implement additional monitoring
5. Conduct security review

### Rotation Failure
1. Check CloudWatch logs for errors
2. Manually rotate if automatic rotation fails
3. Update services with new credentials
4. Fix automation issues
5. Document incident

## Compliance Notes

- All secrets must be classified by data sensitivity
- PII-related secrets require additional encryption
- Financial data access requires audit logging
- Government API credentials may have special requirements
- Regular compliance audits required

---

**Document Version**: 1.0  
**Last Updated**: January 2025  
**Next Review**: April 2025  
**Owner**: DevOps Team