# Secrets Management Configuration for Monitor Legislativo v4
# Uses AWS Secrets Manager with automatic rotation

# Database Credentials
resource "aws_secretsmanager_secret" "db_credentials" {
  name = "${local.cluster_name}-db-credentials"
  description = "PostgreSQL database credentials"
  
  rotation_rules {
    automatically_after_days = 90
  }
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  
  secret_string = jsonencode({
    username = aws_rds_cluster.postgresql.master_username
    password = aws_rds_cluster.postgresql.master_password
    engine   = "postgres"
    host     = aws_rds_cluster.postgresql.endpoint
    port     = 5432
    dbname   = aws_rds_cluster.postgresql.database_name
  })
}

# Redis Authentication
resource "aws_secretsmanager_secret" "redis_auth" {
  name = "${local.cluster_name}-redis-auth"
  description = "Redis authentication token"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = aws_secretsmanager_secret.redis_auth.id
  
  secret_string = jsonencode({
    auth_token = random_password.redis_auth.result
    endpoint   = aws_elasticache_replication_group.redis.primary_endpoint_address
    port       = 6379
  })
}

# Application Secrets
resource "aws_secretsmanager_secret" "app_secrets" {
  name = "${local.cluster_name}-app-secrets"
  description = "Application configuration secrets"
  
  rotation_rules {
    automatically_after_days = 180
  }
  
  tags = local.common_tags
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "random_password" "flask_secret" {
  length  = 64
  special = true
}

resource "random_password" "api_key" {
  length  = 32
  special = false  # API keys typically don't use special chars
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  
  secret_string = jsonencode({
    JWT_SECRET_KEY  = random_password.jwt_secret.result
    FLASK_SECRET_KEY = random_password.flask_secret.result
    API_KEY         = random_password.api_key.result
    ALLOWED_ORIGINS = "https://${var.domain_name},https://api.${var.domain_name}"
  })
}

# OpenSearch Credentials
resource "aws_secretsmanager_secret" "opensearch_credentials" {
  name = "${local.cluster_name}-opensearch-credentials"
  description = "OpenSearch cluster credentials"
  
  tags = local.common_tags
}

resource "random_password" "opensearch_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret_version" "opensearch_credentials" {
  secret_id = aws_secretsmanager_secret.opensearch_credentials.id
  
  secret_string = jsonencode({
    username = "admin"
    password = random_password.opensearch_password.result
    endpoint = aws_opensearch_domain.search.endpoint
  })
}

# External API Keys
resource "aws_secretsmanager_secret" "external_apis" {
  name = "${local.cluster_name}-external-apis"
  description = "External API credentials"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "external_apis" {
  secret_id = aws_secretsmanager_secret.external_apis.id
  
  secret_string = jsonencode({
    # These would be populated with actual API keys
    CAMARA_API_KEY  = ""
    SENADO_API_KEY  = ""
    PLANALTO_API_KEY = ""
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# OAuth Credentials
resource "aws_secretsmanager_secret" "oauth_credentials" {
  name = "${local.cluster_name}-oauth-credentials"
  description = "OAuth provider credentials"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "oauth_credentials" {
  secret_id = aws_secretsmanager_secret.oauth_credentials.id
  
  secret_string = jsonencode({
    # Google OAuth
    GOOGLE_CLIENT_ID     = ""
    GOOGLE_CLIENT_SECRET = ""
    
    # GitHub OAuth (for admin access)
    GITHUB_CLIENT_ID     = ""
    GITHUB_CLIENT_SECRET = ""
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Monitoring Credentials
resource "aws_secretsmanager_secret" "monitoring_credentials" {
  name = "${local.cluster_name}-monitoring-credentials"
  description = "Monitoring and alerting credentials"
  
  tags = local.common_tags
}

resource "random_password" "grafana_password" {
  length  = 24
  special = true
}

resource "aws_secretsmanager_secret_version" "monitoring_credentials" {
  secret_id = aws_secretsmanager_secret.monitoring_credentials.id
  
  secret_string = jsonencode({
    GRAFANA_ADMIN_USER     = "admin"
    GRAFANA_ADMIN_PASSWORD = random_password.grafana_password.result
    
    # Alerting webhooks
    SLACK_WEBHOOK_URL      = ""
    PAGERDUTY_API_KEY      = ""
    EMAIL_SMTP_HOST        = ""
    EMAIL_SMTP_USER        = ""
    EMAIL_SMTP_PASSWORD    = ""
  })
  
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# IAM Policy for accessing secrets
resource "aws_iam_policy" "secrets_access" {
  name        = "${local.cluster_name}-secrets-access"
  description = "Allow access to secrets manager"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.db_credentials.arn,
          aws_secretsmanager_secret.redis_auth.arn,
          aws_secretsmanager_secret.app_secrets.arn,
          aws_secretsmanager_secret.opensearch_credentials.arn,
          aws_secretsmanager_secret.external_apis.arn,
          aws_secretsmanager_secret.oauth_credentials.arn,
          aws_secretsmanager_secret.monitoring_credentials.arn
        ]
      }
    ]
  })
  
  tags = local.common_tags
}

# Service Account for Kubernetes
resource "aws_iam_role" "secrets_manager_sa" {
  name = "${local.cluster_name}-secrets-manager-sa"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub" = "system:serviceaccount:default:secrets-manager"
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "secrets_manager_sa" {
  role       = aws_iam_role.secrets_manager_sa.name
  policy_arn = aws_iam_policy.secrets_access.arn
}

# Kubernetes ConfigMap for non-sensitive configuration
resource "kubernetes_config_map" "app_config" {
  metadata {
    name      = "app-config"
    namespace = "default"
  }
  
  data = {
    APP_ENV          = var.environment
    APP_NAME         = var.cluster_name
    REGION           = var.region
    
    # Database
    DB_HOST          = aws_rds_cluster.postgresql.endpoint
    DB_PORT          = "5432"
    DB_NAME          = aws_rds_cluster.postgresql.database_name
    
    # Redis
    REDIS_HOST       = aws_elasticache_replication_group.redis.primary_endpoint_address
    REDIS_PORT       = "6379"
    
    # OpenSearch
    OPENSEARCH_HOST  = aws_opensearch_domain.search.endpoint
    
    # S3
    S3_STORAGE_BUCKET = aws_s3_bucket.storage.id
    S3_BACKUPS_BUCKET = aws_s3_bucket.backups.id
    
    # Monitoring
    PROMETHEUS_ENABLED = "true"
    METRICS_ENABLED    = "true"
    
    # Feature Flags
    FEATURE_ML_ALERTS  = "true"
    FEATURE_REALTIME   = "true"
    FEATURE_EXPORT_PDF = "true"
  }
  
  depends_on = [module.eks]
}

# Outputs for secret ARNs
output "secrets_arns" {
  description = "ARNs of created secrets"
  value = {
    db_credentials    = aws_secretsmanager_secret.db_credentials.arn
    redis_auth        = aws_secretsmanager_secret.redis_auth.arn
    app_secrets       = aws_secretsmanager_secret.app_secrets.arn
    opensearch        = aws_secretsmanager_secret.opensearch_credentials.arn
    external_apis     = aws_secretsmanager_secret.external_apis.arn
    oauth             = aws_secretsmanager_secret.oauth_credentials.arn
    monitoring        = aws_secretsmanager_secret.monitoring_credentials.arn
  }
  sensitive = true
}

output "secrets_manager_role_arn" {
  description = "IAM role ARN for Kubernetes service account"
  value       = aws_iam_role.secrets_manager_sa.arn
}