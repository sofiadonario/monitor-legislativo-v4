# RDS Aurora PostgreSQL Configuration

resource "aws_rds_cluster" "legislativo_db" {
  cluster_identifier      = "${var.project_name}-${var.environment}-cluster"
  engine                  = "aurora-postgresql"
  engine_version         = "15.4"
  database_name          = "legislativo"
  master_username        = "postgres"
  master_password        = random_password.db_password.result
  
  # Backup configuration
  backup_retention_period = 30
  preferred_backup_window = "03:00-04:00"
  
  # Maintenance window
  preferred_maintenance_window = "sun:04:00-sun:05:00"
  
  # Security
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.db_encryption.arn
  
  # High availability
  availability_zones = data.aws_availability_zones.available.names
  
  # Parameter group
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.legislativo.name
  
  # Subnet group
  db_subnet_group_name = aws_db_subnet_group.legislativo.name
  
  # Security group
  vpc_security_group_ids = [aws_security_group.db.id]
  
  # Deletion protection
  deletion_protection = var.environment == "production" ? true : false
  
  # Performance Insights
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  tags = local.common_tags
}

resource "aws_rds_cluster_instance" "legislativo_instances" {
  count              = var.db_instance_count
  identifier         = "${var.project_name}-${var.environment}-${count.index}"
  cluster_identifier = aws_rds_cluster.legislativo_db.id
  instance_class     = var.db_instance_class
  engine             = aws_rds_cluster.legislativo_db.engine
  engine_version     = aws_rds_cluster.legislativo_db.engine_version
  
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.db_encryption.arn
  
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  tags = local.common_tags
}

resource "aws_rds_cluster_parameter_group" "legislativo" {
  family = "aurora-postgresql15"
  name   = "${var.project_name}-${var.environment}-cluster-pg"
  
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,pgaudit"
  }
  
  parameter {
    name  = "log_statement"
    value = "all"
  }
  
  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries taking more than 1 second
  }
  
  tags = local.common_tags
}

resource "aws_db_subnet_group" "legislativo" {
  name       = "${var.project_name}-${var.environment}-db-subnet"
  subnet_ids = var.private_subnet_ids
  
  tags = local.common_tags
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name = "${var.project_name}-${var.environment}-db-credentials"
  
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  
  secret_string = jsonencode({
    username = aws_rds_cluster.legislativo_db.master_username
    password = random_password.db_password.result
    endpoint = aws_rds_cluster.legislativo_db.endpoint
    reader_endpoint = aws_rds_cluster.legislativo_db.reader_endpoint
    database = aws_rds_cluster.legislativo_db.database_name
  })
}