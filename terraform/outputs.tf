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