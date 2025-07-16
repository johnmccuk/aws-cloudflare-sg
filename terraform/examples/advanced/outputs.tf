# Outputs for the advanced example

# Module outputs
output "security_group_id" {
  description = "ID of the created Cloudflare security group"
  value       = module.cloudflare_security_group.security_group_id
}

output "security_group_arn" {
  description = "ARN of the created Cloudflare security group"
  value       = module.cloudflare_security_group.security_group_arn
}

output "security_group_name" {
  description = "Name of the created Cloudflare security group"
  value       = module.cloudflare_security_group.security_group_name
}

output "cloudflare_ip_count" {
  description = "Number of Cloudflare IP ranges configured"
  value       = module.cloudflare_security_group.cloudflare_ip_count
}

output "configured_ports" {
  description = "List of ports configured in the security group rules"
  value       = module.cloudflare_security_group.configured_ports
}

# Lambda function outputs
output "lambda_function_name" {
  description = "Name of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_arn
}

# Monitoring outputs
output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = module.cloudflare_security_group.sns_topic_arn
}

output "cloudwatch_dashboard_url" {
  description = "URL of the CloudWatch dashboard for monitoring"
  value       = module.cloudflare_security_group.cloudwatch_dashboard_url
}

# EventBridge outputs
output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule for scheduled updates"
  value       = module.cloudflare_security_group.eventbridge_rule_name
}

output "update_schedule" {
  description = "Configured schedule expression for automated updates"
  value       = module.cloudflare_security_group.update_schedule
}

output "automation_enabled" {
  description = "Whether automated updates are enabled"
  value       = module.cloudflare_security_group.automation_enabled
}

# Additional outputs from this example
output "internal_security_group_id" {
  description = "ID of the internal communication security group"
  value       = aws_security_group.internal_communication.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = data.aws_vpc.selected.cidr_block
}

output "deployment_summary" {
  description = "Summary of the deployment configuration"
  value = {
    environment           = var.environment
    vpc_id               = var.vpc_id
    cloudflare_ports     = module.cloudflare_security_group.configured_ports
    automation_enabled   = module.cloudflare_security_group.automation_enabled
    monitoring_enabled   = module.cloudflare_security_group.sns_topic_arn != null
    terraform_mode       = "cloud"
  }
}