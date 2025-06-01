# Terraform Configuration for Legislative Monitor Production Infrastructure
# AWS EKS cluster with supporting services

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }

  backend "s3" {
    bucket = "monitor-legislativo-terraform-state"
    key    = "production/terraform.tfstate"
    region = "us-east-1"
    
    dynamodb_table = "monitor-legislativo-terraform-locks"
    encrypt        = true
  }
}

# Variables
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "monitor-legislativo"
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "monitor-legislativo.gov.br"
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Local values
locals {
  cluster_name = "${var.cluster_name}-${var.environment}"
  
  common_tags = {
    Environment = var.environment
    Project     = "monitor-legislativo"
    ManagedBy   = "terraform"
  }

  azs = slice(data.aws_availability_zones.available.names, 0, 3)
}

# VPC Configuration
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = local.azs
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true

  # EKS tags
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
  }

  tags = local.common_tags
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.28"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  # Encryption
  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }

  # Logging
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Node groups
  eks_managed_node_groups = {
    # General purpose nodes
    general = {
      name = "general"

      instance_types = ["t3.large"]
      
      min_size     = 2
      max_size     = 10
      desired_size = 3

      disk_size = 50
      
      labels = {
        role = "general"
      }

      tags = {
        Environment = var.environment
      }
    }

    # Compute optimized for search
    search = {
      name = "search"

      instance_types = ["c5.xlarge"]
      
      min_size     = 1
      max_size     = 5
      desired_size = 2

      disk_size = 100

      labels = {
        role = "search"
      }

      taints = {
        dedicated = {
          key    = "search"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }

      tags = {
        Environment = var.environment
      }
    }

    # Memory optimized for cache
    cache = {
      name = "cache"

      instance_types = ["r5.large"]
      
      min_size     = 1
      max_size     = 3
      desired_size = 1

      disk_size = 50

      labels = {
        role = "cache"
      }

      taints = {
        dedicated = {
          key    = "cache"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }

      tags = {
        Environment = var.environment
      }
    }
  }

  tags = local.common_tags
}

# KMS Key for EKS encryption
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# RDS Aurora PostgreSQL
resource "aws_rds_subnet_group" "default" {
  name       = "${local.cluster_name}-db-subnet-group"
  subnet_ids = module.vpc.private_subnets

  tags = merge(local.common_tags, {
    Name = "${local.cluster_name}-db-subnet-group"
  })
}

resource "aws_security_group" "rds" {
  name_prefix = "${local.cluster_name}-rds-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_rds_cluster" "postgresql" {
  cluster_identifier      = "${local.cluster_name}-db"
  engine                 = "aurora-postgresql"
  engine_version         = "15.4"
  
  database_name          = "monitor_legislativo"
  master_username        = "postgres"
  manage_master_user_password = true
  
  db_subnet_group_name   = aws_rds_subnet_group.default.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  
  backup_retention_period = 7
  preferred_backup_window = "07:00-09:00"
  
  storage_encrypted      = true
  kms_key_id            = aws_kms_key.rds.arn
  
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "${local.cluster_name}-final-snapshot"

  tags = local.common_tags
}

resource "aws_rds_cluster_instance" "cluster_instances" {
  count              = 2
  identifier         = "${local.cluster_name}-db-${count.index}"
  cluster_identifier = aws_rds_cluster.postgresql.id
  instance_class     = "db.r6g.large"
  engine             = aws_rds_cluster.postgresql.engine
  engine_version     = aws_rds_cluster.postgresql.engine_version
  
  performance_insights_enabled = true
  monitoring_interval          = 60
  monitoring_role_arn         = aws_iam_role.rds_enhanced_monitoring.arn

  tags = local.common_tags
}

resource "aws_kms_key" "rds" {
  description             = "RDS encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.common_tags
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "default" {
  name       = "${local.cluster_name}-cache-subnet"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "elasticache" {
  name_prefix = "${local.cluster_name}-redis-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  tags = local.common_tags
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${local.cluster_name}-redis"
  description                = "Redis cluster for Monitor Legislativo"
  
  port                       = 6379
  parameter_group_name       = "default.redis7"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  
  engine_version             = "7.0"
  
  subnet_group_name          = aws_elasticache_subnet_group.default.name
  security_group_ids         = [aws_security_group.elasticache.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth.result
  
  snapshot_retention_limit   = 7
  snapshot_window           = "03:00-05:00"
  
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = local.common_tags
}

resource "random_password" "redis_auth" {
  length  = 32
  special = true
}

# OpenSearch (Elasticsearch)
resource "aws_opensearch_domain" "search" {
  domain_name    = "${local.cluster_name}-search"
  engine_version = "OpenSearch_2.3"

  cluster_config {
    instance_type            = "t3.medium.search"
    instance_count           = 3
    dedicated_master_enabled = true
    master_instance_type     = "t3.small.search"
    master_instance_count    = 3
    zone_awareness_enabled   = true
    
    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  vpc_options {
    subnet_ids         = module.vpc.private_subnets
    security_group_ids = [aws_security_group.opensearch.id]
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 50
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https = true
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }

  tags = local.common_tags
}

resource "aws_security_group" "opensearch" {
  name_prefix = "${local.cluster_name}-opensearch-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  tags = local.common_tags
}

# S3 Buckets
resource "aws_s3_bucket" "storage" {
  bucket = "${local.cluster_name}-storage"

  tags = local.common_tags
}

resource "aws_s3_bucket_versioning" "storage" {
  bucket = aws_s3_bucket.storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "storage" {
  bucket = aws_s3_bucket.storage.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket" "backups" {
  bucket = "${local.cluster_name}-backups"

  tags = local.common_tags
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "backup_lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_kms_key" "s3" {
  description             = "S3 encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.common_tags
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/eks/${local.cluster_name}/application"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "redis" {
  name              = "/aws/elasticache/${local.cluster_name}"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/${local.cluster_name}"
  retention_in_days = 7

  tags = local.common_tags
}

# IAM Roles
resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${local.cluster_name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# Route53 DNS
resource "aws_route53_zone" "main" {
  name = var.domain_name

  tags = local.common_tags
}

# ACM Certificate
resource "aws_acm_certificate" "main" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  subject_alternative_names = [
    "*.${var.domain_name}"
  ]

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# Outputs
output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "rds_endpoint" {
  description = "RDS cluster endpoint"
  value       = aws_rds_cluster.postgresql.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  sensitive   = true
}

output "opensearch_endpoint" {
  description = "OpenSearch cluster endpoint"
  value       = aws_opensearch_domain.search.endpoint
  sensitive   = true
}

output "s3_storage_bucket" {
  description = "S3 storage bucket name"
  value       = aws_s3_bucket.storage.id
}

output "s3_backups_bucket" {
  description = "S3 backups bucket name"
  value       = aws_s3_bucket.backups.id
}