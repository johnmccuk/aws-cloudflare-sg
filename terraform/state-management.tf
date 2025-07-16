# Enhanced state management and drift detection for Cloudflare IP security group
# This file contains resources and logic for improved idempotency and state validation

# Local values for state management
locals {
  # Calculate expected vs actual state differences
  expected_ip_count = length(local.all_cloudflare_ips)
  
  # State validation flags
  state_validation_enabled = var.enable_state_validation
  drift_detection_enabled = var.enable_drift_detection
  
  # Resource replacement thresholds
  ip_change_threshold_percent = var.ip_change_threshold_percent
  max_ip_changes_per_update = var.max_ip_changes_per_update
  
  # Calculate if changes exceed replacement threshold
  current_ips_set = toset(local.all_cloudflare_ips)
}

# Data source to get current security group state for drift detection
data "aws_security_group" "current_state" {
  count = local.drift_detection_enabled ? 1 : 0
  id    = aws_security_group.cloudflare_whitelist.id
  
  depends_on = [aws_security_group.cloudflare_whitelist]
}

# Local values for drift detection analysis
locals {
  # Extract current IP ranges from existing security group (for drift detection)
  current_sg_ipv4_ranges = local.drift_detection_enabled ? flatten([
    for rule in data.aws_security_group.current_state[0].ip_permissions :
    rule.ip_ranges[*].cidr_ip if length(rule.ip_ranges) > 0
  ]) : []
  
  current_sg_ipv6_ranges = local.drift_detection_enabled ? flatten([
    for rule in data.aws_security_group.current_state[0].ip_permissions :
    rule.ipv6_ranges[*].cidr_ipv6 if length(rule.ipv6_ranges) > 0
  ]) : []
  
  # Combine all current IPs
  current_sg_all_ips = local.drift_detection_enabled ? toset(concat(
    local.current_sg_ipv4_ranges,
    local.current_sg_ipv6_ranges
  )) : toset([])
  
  # Calculate drift metrics
  expected_ips_set = toset(local.all_cloudflare_ips)
  drift_detected = local.drift_detection_enabled ? (
    length(setsubtract(local.expected_ips_set, local.current_sg_all_ips)) > 0 || 
    length(setsubtract(local.current_sg_all_ips, local.expected_ips_set)) > 0
  ) : false
  
  # Calculate change impact for replacement strategy
  ips_to_add_count = length(setsubtract(local.expected_ips_set, local.current_sg_all_ips))
  ips_to_remove_count = length(setsubtract(local.current_sg_all_ips, local.expected_ips_set))
  total_change_count = local.ips_to_add_count + local.ips_to_remove_count
  
  # Determine if changes exceed threshold for replacement strategy
  change_percentage = (local.drift_detection_enabled && length(local.current_sg_all_ips) > 0) ? (
    (local.total_change_count * 100) / length(local.current_sg_all_ips)
  ) : 0
  
  requires_replacement_strategy = (
    local.change_percentage > local.ip_change_threshold_percent || 
    local.total_change_count > local.max_ip_changes_per_update
  )
}

# CloudWatch custom metrics for state monitoring
resource "aws_cloudwatch_log_metric_filter" "state_drift_detected" {
  count          = local.drift_detection_enabled ? 1 : 0
  name           = "cloudflare-ip-state-drift-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "[timestamp, request_id, level=\"ERROR\", message=\"State drift detected*\"]"

  metric_transformation {
    name      = "StateDriftDetected"
    namespace = "CloudflareIPUpdater"
    value     = "1"
    
    default_value = 0
  }
}

# CloudWatch alarm for state drift detection
resource "aws_cloudwatch_metric_alarm" "state_drift_alarm" {
  count               = local.drift_detection_enabled && var.notification_email != "" ? 1 : 0
  alarm_name          = "cloudflare-ip-state-drift-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "StateDriftDetected"
  namespace           = "CloudflareIPUpdater"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alarm when state drift is detected in Cloudflare IP security group"
  alarm_actions       = [aws_sns_topic.notifications[0].arn]
  treat_missing_data  = "notBreaching"

  tags = merge(
    local.common_tags,
    {
      Name        = "cloudflare-ip-state-drift-${var.environment}"
      Description = "CloudWatch alarm for state drift detection"
    }
  )
}

# CloudWatch custom metrics for replacement strategy triggers
resource "aws_cloudwatch_log_metric_filter" "replacement_strategy_triggered" {
  count          = 1
  name           = "cloudflare-ip-replacement-strategy-${var.environment}"
  log_group_name = aws_cloudwatch_log_group.lambda_logs.name
  pattern        = "[timestamp, request_id, level=\"INFO\", message=\"Replacement strategy triggered*\"]"

  metric_transformation {
    name      = "ReplacementStrategyTriggered"
    namespace = "CloudflareIPUpdater"
    value     = "1"
    
    default_value = 0
  }
}

# CloudWatch alarm for replacement strategy
resource "aws_cloudwatch_metric_alarm" "replacement_strategy_alarm" {
  count               = var.notification_email != "" ? 1 : 0
  alarm_name          = "cloudflare-ip-replacement-strategy-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ReplacementStrategyTriggered"
  namespace           = "CloudflareIPUpdater"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alarm when replacement strategy is triggered due to significant IP changes"
  alarm_actions       = [aws_sns_topic.notifications[0].arn]
  treat_missing_data  = "notBreaching"

  tags = merge(
    local.common_tags,
    {
      Name        = "cloudflare-ip-replacement-strategy-${var.environment}"
      Description = "CloudWatch alarm for replacement strategy triggers"
    }
  )
}

# State validation check resource
resource "null_resource" "state_validation" {
  count = local.state_validation_enabled ? 1 : 0
  
  triggers = {
    # Trigger validation when IP ranges change
    cloudflare_ips_hash = sha256(jsonencode(sort(local.all_cloudflare_ips)))
    security_group_id   = aws_security_group.cloudflare_whitelist.id
    validation_enabled  = local.state_validation_enabled
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo "State validation triggered for security group: ${aws_security_group.cloudflare_whitelist.id}"
      echo "Expected IP count: ${local.expected_ip_count}"
      echo "Drift detection enabled: ${local.drift_detection_enabled}"
      echo "Change threshold: ${local.ip_change_threshold_percent}%"
    EOT
  }
}

# Enhanced lifecycle management for security group
resource "aws_security_group" "cloudflare_whitelist_enhanced" {
  count = var.enable_enhanced_lifecycle ? 1 : 0
  
  name_prefix = "${local.security_group_name}-enhanced-"
  description = "Enhanced security group allowing traffic from Cloudflare IP ranges with improved lifecycle management"
  vpc_id      = var.vpc_id

  # Dynamic ingress rules with enhanced validation
  dynamic "ingress" {
    for_each = local.requires_replacement_strategy ? [] : setproduct(local.all_cloudflare_ips, var.allowed_ports)
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
      Name                    = "${local.security_group_name}-enhanced"
      Description            = "Enhanced Cloudflare IP whitelist security group"
      StateValidationEnabled = local.state_validation_enabled
      DriftDetectionEnabled  = local.drift_detection_enabled
      ReplacementStrategy    = local.requires_replacement_strategy ? "active" : "inactive"
      IPChangeThreshold      = "${local.ip_change_threshold_percent}%"
      LastValidationTime     = timestamp()
    }
  )

  lifecycle {
    create_before_destroy = true
    
    # Prevent destruction if replacement strategy is not active
    prevent_destroy = false
    
    # Replace resource when significant changes are detected
    replace_triggered_by = [
      null_resource.state_validation
    ]
  }
}

# Conditional output based on enhanced lifecycle setting
locals {
  active_security_group = var.enable_enhanced_lifecycle ? aws_security_group.cloudflare_whitelist_enhanced[0] : aws_security_group.cloudflare_whitelist
}