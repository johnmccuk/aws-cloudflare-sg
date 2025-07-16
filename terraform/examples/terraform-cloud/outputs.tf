# Outputs for Terraform Cloud Integration Example

# Core Module Outputs
output "security_group_id" {
  description = "ID of the Cloudflare whitelist security group"
  value       = module.cloudflare_security_group.security_group_id
}

output "security_group_arn" {
  description = "ARN of the Cloudflare whitelist security group"
  value       = module.cloudflare_security_group.security_group_arn
}

output "security_group_name" {
  description = "Name of the Cloudflare whitelist security group"
  value       = module.cloudflare_security_group.security_group_name
}

output "cloudflare_ip_count" {
  description = "Number of Cloudflare IP ranges configured"
  value       = module.cloudflare_security_group.cloudflare_ip_count
}

# Lambda Function Outputs
output "lambda_function_name" {
  description = "Name of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function for automated updates"
  value       = module.cloudflare_security_group.lambda_function_arn
}

# EventBridge Outputs
output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule for scheduling"
  value       = module.cloudflare_security_group.eventbridge_rule_name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule for scheduling"
  value       = module.cloudflare_security_group.eventbridge_rule_arn
}

# Monitoring Outputs
output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch dashboard"
  value       = module.cloudflare_security_group.cloudwatch_dashboard_url
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = module.cloudflare_security_group.sns_topic_arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda function"
  value       = module.cloudflare_security_group.cloudwatch_log_group_name
}

# Additional Security Group Outputs
output "internal_security_group_id" {
  description = "ID of the internal communication security group"
  value       = aws_security_group.internal_communication.id
}

output "internal_security_group_arn" {
  description = "ARN of the internal communication security group"
  value       = aws_security_group.internal_communication.arn
}

# Example ALB Outputs (conditional)
output "example_alb_dns_name" {
  description = "DNS name of the example Application Load Balancer"
  value       = var.create_example_alb ? aws_lb.example[0].dns_name : null
}

output "example_alb_arn" {
  description = "ARN of the example Application Load Balancer"
  value       = var.create_example_alb ? aws_lb.example[0].arn : null
}

output "example_alb_zone_id" {
  description = "Zone ID of the example Application Load Balancer"
  value       = var.create_example_alb ? aws_lb.example[0].zone_id : null
}

output "example_target_group_arn" {
  description = "ARN of the example target group"
  value       = var.create_example_alb ? aws_lb_target_group.example[0].arn : null
}

# Validation Results
output "validation_results" {
  description = "Results of configuration validation checks"
  value = {
    terraform_cloud_configured = var.terraform_cloud_token != "" && var.terraform_organization != "" && var.terraform_workspace_id != ""
    automation_enabled        = var.enable_automation
    monitoring_configured     = var.notification_email != ""
    example_resources_created = var.create_example_alb
    vpc_cidr_block           = data.aws_vpc.target.cidr_block
    aws_region               = var.aws_region
    environment              = var.environment
  }
}

# Terraform Cloud Specific Outputs
output "terraform_cloud_workspace_url" {
  description = "URL to the Terraform Cloud workspace"
  value       = "https://app.terraform.io/app/${var.terraform_organization}/workspaces/${var.terraform_workspace_name}"
}

output "terraform_cloud_runs_url" {
  description = "URL to view Terraform Cloud runs for this workspace"
  value       = "https://app.terraform.io/app/${var.terraform_organization}/workspaces/${var.terraform_workspace_name}/runs"
}

# Security Information
output "security_summary" {
  description = "Summary of security configuration"
  value = {
    allowed_ports             = var.allowed_ports
    protocol                 = var.protocol
    cloudflare_ips_configured = module.cloudflare_security_group.cloudflare_ip_count
    automation_schedule      = var.update_schedule
    notification_configured  = var.notification_email != ""
    internal_sg_configured   = true
    vpc_id                   = var.vpc_id
  }
}

# Cost Optimization Information
output "cost_optimization_info" {
  description = "Information for cost optimization"
  value = {
    lambda_memory_mb         = 256
    lambda_timeout_seconds   = 300
    log_retention_days       = var.log_retention_days
    automation_frequency     = var.update_schedule
    monitoring_enabled       = var.notification_email != ""
    estimated_monthly_cost   = "< $5 USD (excluding data transfer)"
  }
}

# Next Steps Information
output "next_steps" {
  description = "Recommended next steps after deployment"
  value = [
    "1. Verify security group rules in AWS Console: https://console.aws.amazon.com/ec2/v2/home#SecurityGroups:groupId=${module.cloudflare_security_group.security_group_id}",
    "2. Check Lambda function logs: https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups/log-group/${replace(module.cloudflare_security_group.cloudwatch_log_group_name, "/", "$252F")}",
    "3. Monitor Terraform Cloud runs: ${local.terraform_cloud_runs_url}",
    "4. Test automation by triggering Lambda manually",
    "5. Verify SNS notifications are received",
    var.create_example_alb ? "6. Configure your application to use the ALB: ${aws_lb.example[0].dns_name}" : "6. Attach security group to your resources"
  ]
}

# Local values for URL construction
locals {
  terraform_cloud_runs_url = "https://app.terraform.io/app/${var.terraform_organization}/workspaces/${var.terraform_workspace_name}/runs"
}