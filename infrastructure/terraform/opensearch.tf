# OpenSearch (Elasticsearch) Configuration

resource "aws_opensearch_domain" "legislativo" {
  domain_name    = "${var.project_name}-${var.environment}"
  engine_version = "OpenSearch_2.9"

  cluster_config {
    instance_type            = var.opensearch_instance_type
    instance_count           = var.opensearch_instance_count
    zone_awareness_enabled   = true
    
    zone_awareness_config {
      availability_zone_count = 3
    }
    
    dedicated_master_enabled = true
    dedicated_master_type    = "m5.large.search"
    dedicated_master_count   = 3
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.opensearch_volume_size
    iops        = 3000
    throughput  = 125
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https                   = true
    tls_security_policy            = "Policy-Min-TLS-1-2-2019-07"
    custom_endpoint_enabled        = false
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    
    master_user_options {
      master_user_name     = "admin"
      master_user_password = random_password.opensearch_password.result
    }
  }

  vpc_options {
    subnet_ids         = slice(var.private_subnet_ids, 0, 3)
    security_group_ids = [aws_security_group.opensearch.id]
  }

  snapshot_options {
    automated_snapshot_start_hour = 3
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_index_slow.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_search_slow.arn
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  tags = local.common_tags
}

resource "random_password" "opensearch_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "opensearch_credentials" {
  name = "${var.project_name}-${var.environment}-opensearch-credentials"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "opensearch_credentials" {
  secret_id = aws_secretsmanager_secret.opensearch_credentials.id
  
  secret_string = jsonencode({
    username = "admin"
    password = random_password.opensearch_password.result
    endpoint = "https://${aws_opensearch_domain.legislativo.endpoint}"
    kibana_endpoint = "https://${aws_opensearch_domain.legislativo.kibana_endpoint}"
  })
}

resource "aws_cloudwatch_log_group" "opensearch_index_slow" {
  name              = "/aws/opensearch/${var.project_name}-${var.environment}/index-slow"
  retention_in_days = 7
  
  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "opensearch_search_slow" {
  name              = "/aws/opensearch/${var.project_name}-${var.environment}/search-slow"
  retention_in_days = 7
  
  tags = local.common_tags
}

# IAM role for OpenSearch
resource "aws_iam_role" "opensearch_cognito" {
  name = "${var.project_name}-${var.environment}-opensearch-cognito"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "es.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "opensearch_cognito" {
  role       = aws_iam_role.opensearch_cognito.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonOpenSearchServiceCognitoAccess"
}