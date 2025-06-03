# Terraform Variables for Monitor Legislativo Infrastructure

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "monitor-legislativo"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs"
  type        = list(string)
}

# RDS Variables
variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_instance_count" {
  description = "Number of RDS instances"
  type        = number
  default     = 2
}

# ElastiCache Variables
variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.r6g.large"
}

variable "redis_cluster_size" {
  description = "Number of Redis nodes"
  type        = number
  default     = 3
}

# OpenSearch Variables
variable "opensearch_instance_type" {
  description = "OpenSearch instance type"
  type        = string
  default     = "m5.large.search"
}

variable "opensearch_instance_count" {
  description = "Number of OpenSearch instances"
  type        = number
  default     = 3
}

variable "opensearch_volume_size" {
  description = "OpenSearch EBS volume size in GB"
  type        = number
  default     = 100
}

# EKS Variables
variable "eks_instance_type" {
  description = "EC2 instance type for EKS nodes"
  type        = string
  default     = "t3.large"
}

variable "eks_desired_size" {
  description = "Desired number of EKS nodes"
  type        = number
  default     = 3
}

variable "eks_min_size" {
  description = "Minimum number of EKS nodes"
  type        = number
  default     = 2
}

variable "eks_max_size" {
  description = "Maximum number of EKS nodes"
  type        = number
  default     = 10
}

variable "eks_disk_size" {
  description = "EKS node disk size in GB"
  type        = number
  default     = 100
}

variable "eks_key_pair_name" {
  description = "EC2 key pair name for EKS nodes"
  type        = string
}

variable "eks_public_access_cidrs" {
  description = "CIDR blocks allowed to access EKS API"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# Tags
variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project     = "Monitor Legislativo"
    Environment = "Production"
    ManagedBy   = "Terraform"
    Team        = "MackIntegridade"
  }
}

locals {
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      Project     = var.project_name
      CreatedAt   = timestamp()
    }
  )
}