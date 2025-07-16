# AWS service limits and quota checking for Cloudflare IP security group
# This file contains logic for handling AWS service limits and quota validation

# Data sources for AWS service quotas
data "aws_servicequotas_service_quota" "security_groups_per_vpc" {
  count        = var.enable_quota_checking ? 1 : 0
  service_code = "vpc"
  quota_code   = "L-E79EC296"  # Security groups per VPC
}

data "aws_servicequotas_service_quota" "rules_per_security_group" {
  count        = var.enable_quota_checking ? 1 : 0
  service_code = "vpc"
  quota_code   = "L-0EA8095F"  # Rules per security group
}

data "aws_servicequotas_service_quota" "lambda_concurrent_executions" {
  count        = var.enable_quota_checking ? 1 : 0
  service_code = "lambda"
  quota_code   = "L-B99A9384"  # Concurrent executions
}

# Get current usage for security groups in the VPC
data "aws_security_groups" "vpc_security_groups" {
  count = var.enable_quota_checking ? 1 : 0
  
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

# Local calculations for quota validation
locals {
  # Service quota limits (with defaults if quota service is unavailable)
  max_security_groups_per_vpc = (var.enable_quota_checking && length(data.aws_servicequotas_service_quota.security_groups_per_vpc) > 0) ? (
    data.aws_servicequotas_service_quota.security_groups_per_vpc[0].value
  ) : 2500
  
  max_rules_per_security_group = (var.enable_quota_checking && length(data.aws_servicequotas_service_quota.rules_per_security_group) > 0) ? (
    data.aws_servicequotas_service_quota.rules_per_security_group[0].value
  ) : 120
  
  max_lambda_concurrent_executions = (var.enable_quota_checking && length(data.aws_servicequotas_service_quota.lambda_concurrent_executions) > 0) ? (
    data.aws_servicequotas_service_quota.lambda_concurrent_executions[0].value
  ) : 1000
  
  # Current usage calculations
  current_security_groups_count = (var.enable_quota_checking && length(data.aws_security_groups.vpc_security_groups) > 0) ? (
    length(data.aws_security_groups.vpc_security_groups[0].ids)
  ) : 0
  
  # Calculate required rules for Cloudflare IPs
  total_cloudflare_ips = length(local.all_cloudflare_ips)
  total_ports = length(var.allowed_ports)
  required_ingress_rules = local.total_cloudflare_ips * local.total_ports
  required_egress_rules = 2  # IPv4 and IPv6 egress rules
  total_required_rules = local.required_ingress_rules + local.required_egress_rules
  
  # Quota validation flags
  security_groups_quota_ok = local.current_security_groups_count < (local.max_security_groups_per_vpc * 0.9)  # 90% threshold
  rules_quota_ok = local.total_required_rules < (local.max_rules_per_security_group * 0.8)  # 80% threshold
  
  # Calculate if we need multiple security groups due to rule limits
  security_groups_needed = ceil(local.total_required_rules / (local.max_rules_per_security_group * 0.8))
  requires_multiple_security_groups = local.security_groups_needed > 1
  
  # Warning thresholds
  rules_approaching_limit = local.total_required_rules > (local.max_rules_per_security_group * 0.7)  # 70% threshold
  security_groups_approaching_limit = local.current_security_groups_count > (local.max_security_groups_per_vpc * 0.8)  # 80% threshold
}

# Validation checks for AWS service quotas
check "security_groups_quota_check" {
  assert {
    condition = !var.enable_quota_checking || local.security_groups_quota_ok
    error_message = "VPC ${var.vpc_id} is approaching the security groups limit. Current: ${local.current_security_groups_count}, Limit: ${local.max_security_groups_per_vpc}"
  }
}

check "security_group_rules_quota_check" {
  assert {
    condition = !var.enable_quota_checking || local.rules_quota_ok
    error_message = "Required security group rules (${local.total_required_rules}) exceed 80% of the limit (${local.max_rules_per_security_group}). Consider reducing ports or splitting into multiple security groups."
  }
}

check "cloudflare_ip_count_reasonable" {
  assert {
    condition = local.total_cloudflare_ips <= var.max_expected_cloudflare_ips
    error_message = "Cloudflare IP count (${local.total_cloudflare_ips}) exceeds expected maximum (${var.max_expected_cloudflare_ips}). This may indicate an issue with IP fetching or unexpected growth."
  }
}

# CloudWatch custom metrics for quota monitoring
resource "aws_cloudwatch_log_metric_filter" "quota_warning" {
  count          = var.enable_quota_checking ? 1 : 0
  name           = "cloudflare-ip-quota-warning-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "[timestamp, request_id, level=\"WARN\", message=\"*quota*\" || message=\"*limit*\"]"

  metric_transformation {
    name      = "QuotaWarning"
    namespace = "CloudflareIPUpdater"
    value     = "1"
    
    default_value = 0
  }
}

# CloudWatch alarm for quota warnings
resource "aws_cloudwatch_metric_alarm" "quota_warning_alarm" {
  count               = var.enable_quota_checking && var.notification_email != "" ? 1 : 0
  alarm_name          = "cloudflare-ip-quota-warning-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "QuotaWarning"
  namespace           = "CloudflareIPUpdater"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alarm when AWS service quota warnings are detected"
  alarm_actions       = [aws_sns_topic.notifications[0].arn]
  treat_missing_data  = "notBreaching"

  tags = merge(
    local.common_tags,
    {
      Name        = "cloudflare-ip-quota-warning-${var.environment}"
      Description = "CloudWatch alarm for AWS service quota warnings"
    }
  )
}

# Multiple security groups for handling large IP lists
resource "aws_security_group" "cloudflare_whitelist_additional" {
  count = local.requires_multiple_security_groups ? local.security_groups_needed - 1 : 0
  
  name_prefix = "${local.security_group_name}-${count.index + 2}-"
  description = "Additional security group for Cloudflare IP ranges (group ${count.index + 2})"
  vpc_id      = var.vpc_id

  # Calculate IP range slice for this security group
  # Distribute IPs evenly across multiple security groups
  dynamic "ingress" {
    for_each = local.requires_multiple_security_groups ? slice(
      setproduct(local.all_cloudflare_ips, var.allowed_ports),
      count.index * floor(length(setproduct(local.all_cloudflare_ips, var.allowed_ports)) / local.security_groups_needed),
      min(
        (count.index + 1) * floor(length(setproduct(local.all_cloudflare_ips, var.allowed_ports)) / local.security_groups_needed),
        length(setproduct(local.all_cloudflare_ips, var.allowed_ports))
      )
    ) : []
    
    content {
      description      = "Cloudflare IP range ${ingress.value[0]} - Port ${ingress.value[1]}"
      from_port        = ingress.value[1]
      to_port          = ingress.value[1]
      protocol         = var.protocol
      cidr_blocks      = can(regex(":", ingress.value[0])) ? [] : [ingress.value[0]]
      ipv6_cidr_blocks = can(regex(":", ingress.value[0])) ? [ingress.value[0]] : []
    }
  }

  # Explicit egress rules
  egress {
    description      = "All outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.security_group_name}-${count.index + 2}"
      Description = "Additional Cloudflare IP whitelist security group (${count.index + 2})"
      GroupNumber = count.index + 2
      TotalGroups = local.security_groups_needed
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Lambda function environment variables for quota management
locals {
  quota_management_env_vars = var.enable_quota_checking ? {
    ENABLE_QUOTA_CHECKING           = "true"
    MAX_RULES_PER_SECURITY_GROUP   = tostring(local.max_rules_per_security_group)
    MAX_SECURITY_GROUPS_PER_VPC    = tostring(local.max_security_groups_per_vpc)
    CURRENT_SECURITY_GROUPS_COUNT  = tostring(local.current_security_groups_count)
    REQUIRES_MULTIPLE_GROUPS       = tostring(local.requires_multiple_security_groups)
    SECURITY_GROUPS_NEEDED         = tostring(local.security_groups_needed)
    RULES_APPROACHING_LIMIT        = tostring(local.rules_approaching_limit)
    MAX_EXPECTED_CLOUDFLARE_IPS    = tostring(var.max_expected_cloudflare_ips)
  } : {
    ENABLE_QUOTA_CHECKING = "false"
  }
}

# Output quota information for monitoring
output "quota_information" {
  description = "AWS service quota information and current usage"
  value = var.enable_quota_checking ? {
    security_groups = {
      current_count = local.current_security_groups_count
      limit         = local.max_security_groups_per_vpc
      usage_percent = round((local.current_security_groups_count / local.max_security_groups_per_vpc) * 100, 2)
      approaching_limit = local.security_groups_approaching_limit
    }
    security_group_rules = {
      required_rules = local.total_required_rules
      limit         = local.max_rules_per_security_group
      usage_percent = round((local.total_required_rules / local.max_rules_per_security_group) * 100, 2)
      approaching_limit = local.rules_approaching_limit
      requires_multiple_groups = local.requires_multiple_security_groups
      groups_needed = local.security_groups_needed
    }
    cloudflare_ips = {
      current_count = local.total_cloudflare_ips
      expected_max  = var.max_expected_cloudflare_ips
      within_expected_range = local.total_cloudflare_ips <= var.max_expected_cloudflare_ips
    }
    quota_checking_disabled = false
  } : {
    security_groups = {
      current_count = 0
      limit         = 0
      usage_percent = 0
      approaching_limit = false
    }
    security_group_rules = {
      required_rules = 0
      limit         = 0
      usage_percent = 0
      approaching_limit = false
      requires_multiple_groups = false
      groups_needed = 0
    }
    cloudflare_ips = {
      current_count = 0
      expected_max  = 0
      within_expected_range = true
    }
    quota_checking_disabled = true
  }
}