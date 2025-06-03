# Network Security Groups and WAF Configuration
# Monitor Legislativo v4
#
# Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
# Organization: MackIntegridade - Integridade e Monitoramento de Políticas Públicas
# Financing: MackPesquisa - Instituto de Pesquisa Mackenzie

# Web Application Firewall (CloudFlare)
resource "cloudflare_zone" "monitor_legislativo" {
  zone = var.domain_name
}

resource "cloudflare_zone_settings_override" "monitor_legislativo" {
  zone_id = cloudflare_zone.monitor_legislativo.id
  
  settings {
    # Security settings
    security_level         = "medium"
    challenge_ttl          = 1800
    browser_check          = "on"
    hotlink_protection     = "on"
    email_obfuscation      = "on"
    server_side_exclude    = "on"
    
    # SSL/TLS settings
    ssl                    = "strict"
    always_use_https       = "on"
    min_tls_version        = "1.2"
    tls_1_3                = "on"
    automatic_https_rewrites = "on"
    
    # Performance settings
    brotli                 = "on"
    minify {
      css  = "on"
      html = "on"
      js   = "on"
    }
    
    # Cache settings
    browser_cache_ttl      = 14400
    always_online          = "on"
  }
}

# WAF Rules
resource "cloudflare_filter" "block_malicious_countries" {
  zone_id     = cloudflare_zone.monitor_legislativo.id
  description = "Block traffic from high-risk countries"
  expression  = "(ip.geoip.country in {\"CN\" \"RU\" \"KP\" \"IR\"})"
}

resource "cloudflare_firewall_rule" "block_malicious_countries" {
  zone_id     = cloudflare_zone.monitor_legislativo.id
  description = "Block malicious countries"
  filter_id   = cloudflare_filter.block_malicious_countries.id
  action      = "block"
  priority    = 1
}

resource "cloudflare_filter" "rate_limit_api" {
  zone_id     = cloudflare_zone.monitor_legislativo.id
  description = "Rate limit API endpoints"
  expression  = "(http.request.uri.path contains \"/api/\")"
}

resource "cloudflare_firewall_rule" "rate_limit_api" {
  zone_id     = cloudflare_zone.monitor_legislativo.id
  description = "Rate limit API calls"
  filter_id   = cloudflare_filter.rate_limit_api.id
  action      = "challenge"
  priority    = 2
}

resource "cloudflare_filter" "block_sql_injection" {
  zone_id     = cloudflare_zone.monitor_legislativo.id
  description = "Block SQL injection attempts"
  expression  = "(http.request.uri.query contains \"union select\" or http.request.uri.query contains \"drop table\" or http.request.uri.query contains \"insert into\")"
}

resource "cloudflare_firewall_rule" "block_sql_injection" {
  zone_id     = cloudflare_zone.monitor_legislativo.id
  description = "Block SQL injection"
  filter_id   = cloudflare_filter.block_sql_injection.id
  action      = "block"
  priority    = 3
}

# AWS Security Groups
resource "aws_security_group" "web_servers" {
  name_prefix = "monitor-legislativo-web-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for web servers"

  # HTTPS from CloudFlare
  ingress {
    description = "HTTPS from CloudFlare"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      "173.245.48.0/20",
      "103.21.244.0/22",
      "103.22.200.0/22",
      "103.31.4.0/22",
      "141.101.64.0/18",
      "108.162.192.0/18",
      "190.93.240.0/20",
      "188.114.96.0/20",
      "197.234.240.0/22",
      "198.41.128.0/17",
      "162.158.0.0/15",
      "104.16.0.0/13",
      "104.24.0.0/14",
      "172.64.0.0/13",
      "131.0.72.0/22"
    ]
  }

  # HTTP redirect to HTTPS
  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [
      "173.245.48.0/20",
      "103.21.244.0/22",
      "103.22.200.0/22",
      "103.31.4.0/22",
      "141.101.64.0/18",
      "108.162.192.0/18",
      "190.93.240.0/20",
      "188.114.96.0/20",
      "197.234.240.0/22",
      "198.41.128.0/17",
      "162.158.0.0/15",
      "104.16.0.0/13",
      "104.24.0.0/14",
      "172.64.0.0/13",
      "131.0.72.0/22"
    ]
  }

  # SSH access only from bastion
  ingress {
    description     = "SSH from bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "monitor-legislativo-web-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

resource "aws_security_group" "database" {
  name_prefix = "monitor-legislativo-db-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for database servers"

  # PostgreSQL from web servers
  ingress {
    description     = "PostgreSQL from web servers"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web_servers.id]
  }

  # PostgreSQL from application servers
  ingress {
    description     = "PostgreSQL from app servers"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  # Minimal outbound for updates
  egress {
    description = "HTTPS for updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP for updates"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "monitor-legislativo-db-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

resource "aws_security_group" "application" {
  name_prefix = "monitor-legislativo-app-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for application servers"

  # HTTP from load balancer
  ingress {
    description     = "HTTP from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Health checks
  ingress {
    description     = "Health checks"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # SSH from bastion
  ingress {
    description     = "SSH from bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "monitor-legislativo-app-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

resource "aws_security_group" "alb" {
  name_prefix = "monitor-legislativo-alb-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for Application Load Balancer"

  # HTTPS from internet
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP from internet (redirect to HTTPS)
  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "monitor-legislativo-alb-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

resource "aws_security_group" "bastion" {
  name_prefix = "monitor-legislativo-bastion-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for bastion host"

  # SSH from admin IPs only
  ingress {
    description = "SSH from admin IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_ip_ranges
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "monitor-legislativo-bastion-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

resource "aws_security_group" "redis" {
  name_prefix = "monitor-legislativo-redis-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for Redis cache"

  # Redis from application servers
  ingress {
    description     = "Redis from app servers"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id, aws_security_group.web_servers.id]
  }

  # No outbound traffic needed for Redis
  tags = {
    Name         = "monitor-legislativo-redis-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

resource "aws_security_group" "monitoring" {
  name_prefix = "monitor-legislativo-monitoring-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for monitoring services"

  # Prometheus
  ingress {
    description = "Prometheus from admin"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = var.admin_ip_ranges
  }

  # Grafana
  ingress {
    description = "Grafana from admin"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = var.admin_ip_ranges
  }

  # Node exporter from Prometheus
  ingress {
    description = "Node exporter"
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    self        = true
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "monitor-legislativo-monitoring-sg"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "monitor_legislativo" {
  name  = "monitor-legislativo-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - SQL Injection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Custom rule for blocking specific countries
  rule {
    name     = "BlockMaliciousCountries"
    priority = 40

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = ["CN", "RU", "KP", "IR"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockMaliciousCountriesMetric"
      sampled_requests_enabled   = true
    }
  }

  # Custom rule for protecting admin paths
  rule {
    name     = "ProtectAdminPaths"
    priority = 50

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string = "/admin"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "STARTS_WITH"
          }
        }
        statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.admin_ips.arn
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ProtectAdminPathsMetric"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name         = "monitor-legislativo-waf"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "MonitorLegislativoWAF"
    sampled_requests_enabled   = true
  }
}

# IP Set for admin IPs
resource "aws_wafv2_ip_set" "admin_ips" {
  name               = "monitor-legislativo-admin-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.admin_ip_ranges

  tags = {
    Name         = "monitor-legislativo-admin-ips"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "monitor_legislativo" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.monitor_legislativo.arn
}

# CloudWatch Log Group for WAF
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/wafv2/monitor-legislativo"
  retention_in_days = 30

  tags = {
    Name         = "monitor-legislativo-waf-logs"
    Environment  = var.environment
    Project      = "Monitor Legislativo v4"
    Developers   = "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães"
    Organization = "MackIntegridade"
    Financing    = "MackPesquisa"
  }
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "monitor_legislativo" {
  resource_arn            = aws_wafv2_web_acl.monitor_legislativo.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}