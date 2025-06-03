# ElastiCache Redis Configuration

resource "aws_elasticache_replication_group" "legislativo_redis" {
  replication_group_id       = "${var.project_name}-${var.environment}-redis"
  replication_group_description = "Redis cluster for Legislative Monitor"
  
  engine               = "redis"
  engine_version       = "7.0"
  parameter_group_name = aws_elasticache_parameter_group.legislativo_redis.name
  port                 = 6379
  
  # Node configuration
  node_type = var.redis_node_type
  number_cache_clusters = var.redis_cluster_size
  
  # High availability
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  # Security
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                = random_password.redis_auth.result
  
  # Subnet group
  subnet_group_name = aws_elasticache_subnet_group.legislativo.name
  
  # Security group
  security_group_ids = [aws_security_group.redis.id]
  
  # Backup
  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"
  
  # Maintenance
  maintenance_window = "sun:05:00-sun:07:00"
  
  # Notifications
  notification_topic_arn = aws_sns_topic.alerts.arn
  
  # Logging
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
  
  tags = local.common_tags
}

resource "aws_elasticache_parameter_group" "legislativo_redis" {
  family = "redis7"
  name   = "${var.project_name}-${var.environment}-redis-pg"
  
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
  
  parameter {
    name  = "timeout"
    value = "300"
  }
  
  parameter {
    name  = "tcp-keepalive"
    value = "60"
  }
  
  parameter {
    name  = "notify-keyspace-events"
    value = "Ex"
  }
}

resource "aws_elasticache_subnet_group" "legislativo" {
  name       = "${var.project_name}-${var.environment}-redis-subnet"
  subnet_ids = var.private_subnet_ids
}

resource "random_password" "redis_auth" {
  length  = 32
  special = false # Redis auth tokens don't support special characters
}

resource "aws_secretsmanager_secret" "redis_credentials" {
  name = "${var.project_name}-${var.environment}-redis-credentials"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "redis_credentials" {
  secret_id = aws_secretsmanager_secret.redis_credentials.id
  
  secret_string = jsonencode({
    auth_token = random_password.redis_auth.result
    primary_endpoint = aws_elasticache_replication_group.legislativo_redis.primary_endpoint_address
    reader_endpoint = aws_elasticache_replication_group.legislativo_redis.reader_endpoint_address
    configuration_endpoint = aws_elasticache_replication_group.legislativo_redis.configuration_endpoint_address
  })
}

resource "aws_cloudwatch_log_group" "redis_slow_log" {
  name              = "/aws/elasticache/${var.project_name}-${var.environment}/redis/slow-log"
  retention_in_days = 7
  
  tags = local.common_tags
}