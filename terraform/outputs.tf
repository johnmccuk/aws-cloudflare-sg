# Output definitions for Cloudflare whitelist security group
# Resources referenced here will be created in subsequent tasks

output "security_group_id" {
  description = "ID of the created Cloudflare whitelist security group"
  value       = aws_security_group.cloudflare_whitelist.id
}

output "security_group_arn" {
  description = "ARN of the created Cloudflare whitelist security group"
  value       = aws_security_group.cloudflare_whitelist.arn
}

output "security_group_name" {
  description = "Name of the created Cloudflare whitelist security group"
  value       = aws_security_group.cloudflare_whitelist.name
}

output "cloudflare_ip_count" {
  description = "Number of Cloudflare IP ranges configured in the security group"
  value       = length(local.all_cloudflare_ips)
}

output "configured_ports" {
  description = "List of ports configured in the security group rules"
  value       = var.allowed_ports
}

output "protocol" {
  description = "Protocol configured for the security group rules"
  value       = var.protocol
}

# Lambda function outputs
output "lambda_function_name" {
  description = "Name of the Lambda function for automated updates"
  value       = aws_lambda_function.cloudflare_updater.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function for automated updates"
  value       = aws_lambda_function.cloudflare_updater.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications (if configured)"
  value       = var.notification_email != "" ? aws_sns_topic.notifications[0].arn : null
}

# EventBridge outputs
output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule for scheduled updates"
  value       = aws_cloudwatch_event_rule.cloudflare_update_schedule.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for scheduled updates"
  value       = aws_cloudwatch_event_rule.cloudflare_update_schedule.arn
}

output "update_schedule" {
  description = "Configured schedule expression for automated updates"
  value       = var.update_schedule
}

output "automation_enabled" {
  description = "Whether automated updates are enabled"
  value       = var.enable_automation
}

# CloudWatch monitoring outputs
output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda function"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for Lambda function"
  value       = aws_cloudwatch_log_group.lambda_logs.arn
}

output "cloudwatch_error_alarm_name" {
  description = "Name of the CloudWatch alarm for Lambda errors (if configured)"
  value       = var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_error_alarm[0].alarm_name : null
}

output "cloudwatch_duration_alarm_name" {
  description = "Name of the CloudWatch alarm for Lambda duration (if configured)"
  value       = var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_duration_alarm[0].alarm_name : null
}

output "cloudwatch_throttle_alarm_name" {
  description = "Name of the CloudWatch alarm for Lambda throttles (if configured)"
  value       = var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_throttle_alarm[0].alarm_name : null
}

output "cloudwatch_success_alarm_name" {
  description = "Name of the CloudWatch alarm for monitoring automation health (if configured)"
  value       = var.notification_email != "" ? aws_cloudwatch_metric_alarm.lambda_success_alarm[0].alarm_name : null
}

output "cloudwatch_dashboard_name" {
  description = "Name of the CloudWatch dashboard for monitoring (if configured)"
  value       = var.notification_email != "" ? aws_cloudwatch_dashboard.cloudflare_updater[0].dashboard_name : null
}

output "cloudwatch_dashboard_url" {
  description = "URL of the CloudWatch dashboard for monitoring (if configured)"
  value       = var.notification_email != "" ? "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.cloudflare_updater[0].dashboard_name}" : null
}

# Enhanced state management outputs
output "state_management_status" {
  description = "Status of enhanced state management features"
  value = {
    state_validation_enabled = var.enable_state_validation
    drift_detection_enabled  = var.enable_drift_detection
    enhanced_lifecycle_enabled = var.enable_enhanced_lifecycle
    ip_change_threshold_percent = var.ip_change_threshold_percent
    max_ip_changes_per_update = var.max_ip_changes_per_update
  }
}

# Additional security group outputs for multiple groups scenario
output "additional_security_group_ids" {
  description = "IDs of additional security groups (if multiple groups are required)"
  value       = local.requires_multiple_security_groups ? aws_security_group.cloudflare_whitelist_additional[*].id : []
}

output "total_security_groups_created" {
  description = "Total number of security groups created for Cloudflare IP ranges"
  value       = 1 + (local.requires_multiple_security_groups ? length(aws_security_group.cloudflare_whitelist_additional) : 0)
}

# Cleanup and destroy functionality outputs
output "cleanup_function_name" {
  description = "Name of the cleanup Lambda function (if automation is enabled)"
  value       = var.enable_automation ? aws_lambda_function.cleanup_function[0].function_name : null
}

output "cleanup_function_arn" {
  description = "ARN of the cleanup Lambda function (if automation is enabled)"
  value       = var.enable_automation ? aws_lambda_function.cleanup_function[0].arn : null
}

output "cleanup_resources_inventory" {
  description = "Inventory of all resources that will be cleaned up during destroy"
  value = {
    security_groups = concat(
      [aws_security_group.cloudflare_whitelist.id],
      local.requires_multiple_security_groups ? aws_security_group.cloudflare_whitelist_additional[*].id : []
    )
    lambda_functions = concat(
      [aws_lambda_function.cloudflare_updater.function_name],
      var.enable_automation ? [aws_lambda_function.cleanup_function[0].function_name] : []
    )
    cloudwatch_log_groups = concat(
      [aws_cloudwatch_log_group.lambda_logs.name],
      var.enable_automation ? [aws_cloudwatch_log_group.cleanup_lambda_logs[0].name] : []
    )
    sns_topics = var.notification_email != "" ? [aws_sns_topic.notifications[0].arn] : []
    eventbridge_rules = [aws_cloudwatch_event_rule.cloudflare_update_schedule.name]
    cloudwatch_alarms = var.notification_email != "" ? [
      aws_cloudwatch_metric_alarm.lambda_error_alarm[0].alarm_name,
      aws_cloudwatch_metric_alarm.lambda_duration_alarm[0].alarm_name,
      aws_cloudwatch_metric_alarm.lambda_throttle_alarm[0].alarm_name,
      aws_cloudwatch_metric_alarm.lambda_success_alarm[0].alarm_name
    ] : []
    cloudwatch_dashboards = var.notification_email != "" ? [
      aws_cloudwatch_dashboard.cloudflare_updater[0].dashboard_name
    ] : []
    iam_roles = concat(
      [aws_iam_role.lambda_execution_role.name],
      var.enable_automation ? [aws_iam_role.cleanup_lambda_role[0].name] : []
    )
  }
}

output "cleanup_tags" {
  description = "Tags used to identify resources for cleanup operations"
  value = {
    CleanupGroup = "cloudflare-ip-updater-${var.environment}"
    ResourceType = "automation"
    DestroyOrder = "managed"
    Module       = "cloudflare-aws-security-group"
    Component    = "core"
    Cleanup      = "required"
  }
}

output "destroy_instructions" {
  description = "Instructions for proper resource destruction"
  value = {
    manual_cleanup_steps = [
      "1. Disable EventBridge rule to stop new Lambda executions",
      "2. Wait for running Lambda executions to complete (60 seconds)",
      "3. Remove security group rules to avoid dependency conflicts",
      "4. Run 'terraform destroy' to remove all resources",
      "5. Verify all resources are properly cleaned up"
    ]
    automated_cleanup_available = var.enable_automation
    cleanup_lambda_function = var.enable_automation ? aws_lambda_function.cleanup_function[0].function_name : null
    pre_destroy_cleanup_enabled = true
    post_destroy_verification_enabled = true
  }
}